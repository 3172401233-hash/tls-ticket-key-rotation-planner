from typing import List, Optional, Tuple

from .coverage import check_decryption_coverage
from .model import (
    NodeReport,
    Phase,
    PhaseEvent,
    PhaseStatus,
    Risk,
    RiskLevel,
    RISK_LEVEL_ORDER,
    RollbackPoint,
    RotationConfig,
    RotationPlan,
)


def _validate(config):  # type: (RotationConfig) -> None
    if config.max_ticket_lifetime <= 0:
        raise ValueError("max_ticket_lifetime 必须为正数")
    if config.ticket_age < 0:
        raise ValueError("ticket_age 不能为负数")
    if config.destroy_at < config.rotation_start_at:
        raise ValueError("destroy_at 不能早于 rotation_start_at")
    for name, value in (
        ("recovered_traffic_ratio", config.recovered_traffic_ratio),
        ("unknown_key_ratio", config.unknown_key_ratio),
        ("max_unknown_key_ratio", config.max_unknown_key_ratio),
        ("min_recovered_traffic_ratio", config.min_recovered_traffic_ratio),
    ):
        if not 0.0 <= value <= 1.0:
            raise ValueError("%s 必须位于 [0, 1] 区间" % name)
    if config.offline_grace < 0 or config.clock_skew_margin < 0:
        raise ValueError("时间裕量不能为负数")
    if not config.node_reports:
        raise ValueError("至少需要一个入口节点的上报数据")
    ids = [report.node_id for report in config.node_reports]
    if len(set(ids)) != len(ids):
        raise ValueError("node_id 必须唯一")
    unknown = set(config.retired_node_ids) - set(ids)
    if unknown:
        raise ValueError("retired_node_ids 包含未知节点: %s" % sorted(unknown))


def _classify_fleet(
    config,  # type: RotationConfig
):
    # type: (...) -> Tuple[List[NodeReport], List[str], List[str], Optional[float]]
    retired = set(config.retired_node_ids)
    active = [r for r in config.node_reports if r.node_id not in retired]
    offline = [r.node_id for r in active if r.effective_at is None]

    effective_times = sorted(r.effective_at for r in active if r.effective_at is not None)
    threshold = None
    late = []
    if effective_times:
        # 以 P95 生效时间为基线，只有超出基线加离线宽限的实例才算长尾，
        # 避免把正常批次抖动误报为延迟。
        # 排除末尾 5% 的样本后取 P95，避免小样本下 P95 直接等于最大值，
        # 导致唯一的长尾实例被基线自身吸收。
        percentile_index = min(
            len(effective_times) - 1,
            max(0, int(0.95 * len(effective_times)) - 1),
        )
        p95 = effective_times[percentile_index]
        threshold = p95 + config.offline_grace
        late = [
            r.node_id
            for r in active
            if r.effective_at is not None and r.effective_at > threshold
        ]

    distribution_done_at = max(effective_times) if effective_times and not offline else None
    return active, offline, late, distribution_done_at


def _event(phase, planned_at, earliest_safe_at, gate, status, detail):
    return PhaseEvent(
        phase=phase,
        planned_at=planned_at,
        earliest_safe_at=earliest_safe_at,
        gate=gate,
        status=status,
        detail=detail,
    )


def _status_for(earliest_safe_at, now, blocked):
    if blocked:
        return PhaseStatus.BLOCKED
    if now is None or earliest_safe_at is None or now < earliest_safe_at:
        return PhaseStatus.PENDING
    return PhaseStatus.COMPLETE


def build_plan(config):  # type: (RotationConfig) -> RotationPlan
    _validate(config)
    now = config.now
    risks = []  # type: List[Risk]

    active, offline_nodes, late_nodes, distribution_done_at = _classify_fleet(config)
    fleet_ready = not offline_nodes

    observed_ticket_age = min(config.ticket_age, config.max_ticket_lifetime)
    if config.ticket_age > config.max_ticket_lifetime:
        risks.append(
            Risk(
                RiskLevel.HIGH,
                "ticket_age_exceeds_lifetime",
                "上报票据年龄 %.0fs 超过最长票据周期 %.0fs，已按周期上限裁剪，"
                "说明客户端存在时钟漂移或票据续期异常。"
                % (config.ticket_age, config.max_ticket_lifetime),
                "以最长票据周期计算保留窗口，并排查时钟漂移客户端。",
            )
        )

    for node_id in offline_nodes:
        risks.append(
            Risk(
                RiskLevel.CRITICAL,
                "node_not_acked",
                "节点 %s 未确认新密钥生效（离线或延迟上线），轮换不得视为完成。" % node_id,
                "等待实例恢复并确认生效；确认永久下线则加入 retired_node_ids 后再重算。",
            )
        )

    if late_nodes:
        preview = ", ".join(late_nodes[:5])
        if len(late_nodes) > 5:
            preview += " 等 %d 个节点" % len(late_nodes)
        risks.append(
            Risk(
                RiskLevel.MEDIUM,
                "node_late_effective",
                "节点 %s 的生效时间超出 P95 长尾阈值，分发阶段存在长尾延迟。" % preview,
                "核对实例健康度与配置推送通道，避免后续批次再次掉队。",
            )
        )

    if config.retired_node_ids:
        risks.append(
            Risk(
                RiskLevel.LOW,
                "retired_nodes_excluded",
                "节点 %s 已按退役处理，不参与门控统计。"
                % ", ".join(sorted(config.retired_node_ids)),
                "确认退役实例确实已摘除流量，避免残留实例仍在签发旧票据。",
            )
        )

    # ---- 时间线计算 -----------------------------------------------------
    decrypt_new_at = (
        distribution_done_at + config.decryption_hold
        if distribution_done_at is not None
        else None
    )
    issue_new_at = decrypt_new_at
    practical_stop = (
        issue_new_at + observed_ticket_age + config.clock_skew_margin
        if issue_new_at is not None
        else None
    )
    safe_stop = (
        issue_new_at + config.max_ticket_lifetime + config.clock_skew_margin
        if issue_new_at is not None
        else None
    )
    safe_destroy = safe_stop

    # ---- 可观测性门控 ---------------------------------------------------
    unknown_bad = config.unknown_key_ratio > config.max_unknown_key_ratio
    if unknown_bad:
        risks.append(
            Risk(
                RiskLevel.HIGH,
                "unknown_key_ratio_high",
                "未知密钥率 %.2f%% 超过阈值 %.2f%%，可能有节点未加载新密钥或存在异常密钥。"
                % (config.unknown_key_ratio * 100.0, config.max_unknown_key_ratio * 100.0),
                "暂停签发切换，按节点维度排查 unknown_key 指标来源。",
            )
        )

    recovery_bad = config.recovered_traffic_ratio < config.min_recovered_traffic_ratio
    if recovery_bad:
        risks.append(
            Risk(
                RiskLevel.HIGH,
                "recovery_ratio_low",
                "票据恢复流量比例 %.2f%% 低于门限 %.2f%%，切换会放大会话恢复失败。"
                % (
                    config.recovered_traffic_ratio * 100.0,
                    config.min_recovered_traffic_ratio * 100.0,
                ),
                "暂停签发切换，先恢复票据恢复率并确认没有节点只做全量握手。",
            )
        )

    # ---- 提前销毁检查 ---------------------------------------------------
    early_destroy = safe_destroy is not None and config.destroy_at < safe_destroy
    if early_destroy:
        risks.append(
            Risk(
                RiskLevel.CRITICAL,
                "old_key_destroyed_early",
                "计划销毁时间 %.0f 早于安全销毁时间 %.0f，差距 %.0fs；"
                "仍在生命周期内的旧票据将无法解密。"
                % (config.destroy_at, safe_destroy, safe_destroy - config.destroy_at),
                "将销毁任务推迟到 %.0f 之后，旧密钥至少保留一个最长票据周期加时钟裕量。"
                % safe_destroy,
            )
        )

    # ---- 阶段时间表 -----------------------------------------------------
    if fleet_ready:
        confirmed = len(active)
        distribute_detail = "全部 %d 个在线节点均已确认新密钥生效" % confirmed
        distribute_status = _status_for(distribution_done_at, now, False)
    elif distribution_done_at is None and not any(
        r.effective_at is not None for r in active
    ):
        distribute_detail = "尚无节点确认生效，分发未开始或全部实例离线"
        distribute_status = PhaseStatus.BLOCKED
    else:
        confirmed = sum(1 for r in active if r.effective_at is not None)
        distribute_detail = "仅 %d/%d 个在线节点确认生效，等待离线/延迟实例" % (
            confirmed,
            len(active),
        )
        distribute_status = PhaseStatus.IN_PROGRESS

    timetable = [
        _event(
            Phase.DISTRIBUTE,
            distribution_done_at,
            distribution_done_at,
            "全部在线节点 effective_at 到齐（离线节点不得忽略）",
            distribute_status,
            distribute_detail,
        )
    ]

    gate_blocked = not fleet_ready or unknown_bad or recovery_bad
    blocked_phases = {
        Phase.DECRYPT_NEW: not fleet_ready,
        Phase.ISSUE_NEW: gate_blocked,
        Phase.STOP_DECRYPT_OLD: not fleet_ready or early_destroy,
        Phase.DESTROY_OLD: not fleet_ready or early_destroy,
    }

    timetable.append(
        _event(
            Phase.DECRYPT_NEW,
            decrypt_new_at,
            decrypt_new_at,
            "新密钥在所有在线节点进入解密环（与旧密钥并存）",
            _status_for(decrypt_new_at, now, blocked_phases[Phase.DECRYPT_NEW]),
            "新旧密钥并存解密，此阶段不改变签发密钥",
        )
    )
    issue_gate_text = (
        "全量分发完成；unknown_key_ratio <= %.2f%%；"
        "recovered_traffic_ratio >= %.2f%%"
        % (
            config.max_unknown_key_ratio * 100.0,
            config.min_recovered_traffic_ratio * 100.0,
        )
    )
    timetable.append(
        _event(
            Phase.ISSUE_NEW,
            issue_new_at,
            issue_new_at,
            issue_gate_text,
            _status_for(issue_new_at, now, blocked_phases[Phase.ISSUE_NEW]),
            "新节点开始用新密钥签发票据，旧密钥继续解密",
        )
    )
    if practical_stop is None or safe_stop is None:
        stop_detail = "等待全量分发完成后才能计算旧密钥保留窗口"
    else:
        stop_detail = (
            "保守安全时间基于最长票据周期 %.0fs；观测 P99 票据年龄 %.0fs，"
            "实操可提前至 T+%.0fs"
            % (
                config.max_ticket_lifetime,
                observed_ticket_age,
                practical_stop - config.rotation_start_at,
            )
        )
    timetable.append(
        _event(
            Phase.STOP_DECRYPT_OLD,
            practical_stop,
            safe_stop,
            "切换签发后旧票据全部自然过期（最长票据周期 + 时钟裕量）",
            _status_for(safe_stop, now, blocked_phases[Phase.STOP_DECRYPT_OLD]),
            stop_detail,
        )
    )
    timetable.append(
        _event(
            Phase.DESTROY_OLD,
            config.destroy_at,
            safe_destroy,
            "销毁时间不得早于旧密钥安全停止解密时间",
            _status_for(safe_destroy, now, blocked_phases[Phase.DESTROY_OLD]),
            (
                "安全销毁时间 T+%.0fs；当前计划 T+%.0fs"
                % (
                    safe_destroy - config.rotation_start_at,
                    config.destroy_at - config.rotation_start_at,
                )
                if safe_destroy is not None
                else "等待全量分发完成后才能计算安全销毁时间；当前计划 T+%.0fs"
                % (config.destroy_at - config.rotation_start_at)
            ),
        )
    )

    # ---- 回滚点 ---------------------------------------------------------
    rollback_points = [
        RollbackPoint(
            "RB1",
            "签发切换前",
            Phase.ISSUE_NEW,
            issue_new_at,
            "将签发密钥回退为旧密钥，新密钥仅保留在解密环中。",
            "无票据兼容性影响，仅推迟轮换。",
            fleet_ready,
        ),
        RollbackPoint(
            "RB2",
            "旧密钥停止解密前",
            Phase.STOP_DECRYPT_OLD,
            safe_stop,
            "重新把旧密钥加入全部节点的解密环，并恢复旧密钥签发。",
            "切换后签发的新票据仍可由新密钥解密，恢复期间双密钥并存。",
            fleet_ready and issue_new_at is not None,
        ),
        RollbackPoint(
            "RB3",
            "旧密钥销毁前",
            Phase.DESTROY_OLD,
            safe_destroy,
            "取消销毁任务并保留旧密钥材料；销毁一旦执行，回滚窗口永久关闭。",
            "销毁后只能要求受影响客户端重新做全量握手。",
            fleet_ready and not early_destroy,
        ),
    ]

    # ---- 解密覆盖模拟 ---------------------------------------------------
    violations = check_decryption_coverage(
        config, issue_new_at, safe_stop, safe_destroy
    )

    risks.sort(key=lambda risk: RISK_LEVEL_ORDER[risk.level])
    is_safe = (
        fleet_ready
        and not early_destroy
        and not violations
        and not unknown_bad
        and not recovery_bad
    )

    return RotationPlan(
        timetable=timetable,
        risks=risks,
        rollback_points=rollback_points,
        violations=violations,
        distribution_done_at=distribution_done_at,
        issue_new_at=issue_new_at,
        practical_stop_decrypt_at=practical_stop,
        safe_stop_decrypt_at=safe_stop,
        safe_destroy_at=safe_destroy,
        fleet_ready=fleet_ready,
        offline_nodes=offline_nodes,
        late_nodes=late_nodes,
        is_safe=is_safe,
    )
