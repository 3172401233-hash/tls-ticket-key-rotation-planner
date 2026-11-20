from typing import List, Optional, Tuple

from .model import CoverageViolation, NodeReport, RotationConfig


def _online_intervals(
    report: NodeReport, rotation_start_at: float, horizon: float
) -> List[Tuple[float, float]]:
    """按心跳推断节点在线区间。

    没有心跳数据时视为全程在线，避免因缺少心跳输入而掩盖真正的密钥缺口；
    节点在新密钥生效前离线、之后再上线的窗口由调用方显式建模。
    """

    if report.last_seen_at is None:
        return [(rotation_start_at, horizon)]
    if report.last_seen_at < rotation_start_at:
        return []
    if report.effective_at is not None and report.last_seen_at < report.effective_at:
        return [(rotation_start_at, report.last_seen_at)]
    return [(rotation_start_at, horizon)]


def _serves_at(intervals, at):  # type: ignore[no-untyped-def]
    for start, end in intervals:
        if start <= at <= end:
            return True
    return False


def check_decryption_coverage(
    config,  # type: RotationConfig
    issue_new_at,  # type: Optional[float]
    safe_stop_decrypt_at,  # type: Optional[float]
    safe_destroy_at,  # type: float
):
    # type: (...) -> List[CoverageViolation]
    """模拟票据签发/出示时间线，逐节点验证解密密钥始终可定位。

    - 旧代票据：可能在切换签发之前的任意时刻签发，最长保留
      ``max_ticket_lifetime``；
    - 新代票据：最早在 ``issue_new_at`` 签发，到检查窗口末尾仍可能被出示；
    - 旧密钥在 ``safe_stop_decrypt_at`` 后移出解密环，在
      ``config.destroy_at`` 销毁；若该销毁时间早于安全销毁时间，即构成
      “旧密钥提前销毁”，所有仍在生命周期内的旧票据都会无解。
    """

    violations = []
    retired = set(config.retired_node_ids)
    active_reports = [r for r in config.node_reports if r.node_id not in retired]
    if not active_reports or issue_new_at is None:
        return violations

    max_life = config.max_ticket_lifetime
    horizon = safe_destroy_at + max_life + config.clock_skew_margin
    old_ticket_window_end = issue_new_at + max_life + config.clock_skew_margin

    # 旧票据：用边界 + 粗网格覆盖，网格粒度远小于票据周期即可暴露窗口缺口。
    old_check_points = [issue_new_at, old_ticket_window_end]
    step = max(1.0, max_life / 16.0)
    cursor = config.rotation_start_at
    while cursor < old_ticket_window_end:
        old_check_points.append(cursor)
        cursor += step

    for report in active_reports:
        intervals = _online_intervals(report, config.rotation_start_at, horizon)

        # 新代票据：节点在分发确认之前就收到新票据属于协议上不可能但需防御。
        for at in (issue_new_at, horizon):
            if not _serves_at(intervals, at):
                continue
            if report.effective_at is None or report.effective_at > issue_new_at:
                violations.append(
                    CoverageViolation(
                        node_id=report.node_id,
                        at=at,
                        ticket_generation="new",
                        issued_at=issue_new_at,
                        reason="节点尚未确认新密钥生效，无法解密新代票据",
                    )
                )
                break

        for at in old_check_points:
            if at > old_ticket_window_end or not _serves_at(intervals, at):
                continue
            if at <= issue_new_at:
                continue

            issued_at = min(at, issue_new_at)
            ticket_expiry = issued_at + max_life
            if at > ticket_expiry:
                continue

            if safe_stop_decrypt_at is not None and at >= safe_stop_decrypt_at:
                violations.append(
                    CoverageViolation(
                        node_id=report.node_id,
                        at=at,
                        ticket_generation="old",
                        issued_at=issued_at,
                        reason="旧密钥已停止解密，但仍有处于生命周期内的旧票据",
                    )
                )
                continue

            if at >= config.destroy_at:
                base = config.rotation_start_at
                violations.append(
                    CoverageViolation(
                        node_id=report.node_id,
                        at=at,
                        ticket_generation="old",
                        issued_at=issued_at,
                        reason=(
                            "旧密钥已于 T+%.0fs 销毁，早于安全销毁时间 T+%.0fs，"
                            "存活旧票据无法解密"
                        )
                        % (
                            config.destroy_at - base,
                            safe_destroy_at - base,
                        ),
                    )
                )

    return violations
