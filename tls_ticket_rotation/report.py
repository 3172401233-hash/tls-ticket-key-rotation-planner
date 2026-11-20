from .model import (
    PHASE_LABELS,
    PHASE_STATUS_LABELS,
    RISK_LEVEL_LABELS,
    RotationConfig,
    RotationPlan,
)


def _fmt_time(value, base=0.0):
    if value is None:
        return "未排期"
    return "T+%.0fs" % (value - base)


def render_timetable(plan, base=0.0):  # type: (RotationPlan, float) -> str
    headers = ("阶段", "计划时间", "最早安全时间", "状态", "门控条件", "说明")
    rows = [headers]
    for event in plan.timetable:
        rows.append(
            (
                PHASE_LABELS[event.phase],
                _fmt_time(event.planned_at, base),
                _fmt_time(event.earliest_safe_at, base),
                PHASE_STATUS_LABELS[event.status],
                event.gate,
                event.detail,
            )
        )

    widths = [0] * len(headers)
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def line(row):
        return " | ".join(cell.ljust(widths[index]) for index, cell in enumerate(row))

    separator = "-+-".join("-" * width for width in widths)
    output = [line(rows[0]), separator]
    output.extend(line(row) for row in rows[1:])
    return "\n".join(output)


def render_risks(plan):  # type: (RotationPlan) -> str
    if not plan.risks:
        return "未发现兼容性风险。"
    lines = []
    for index, risk in enumerate(plan.risks, start=1):
        lines.append(
            "%d. [%s] %s\n   缓解：%s"
            % (
                index,
                RISK_LEVEL_LABELS[risk.level],
                risk.message,
                risk.mitigation,
            )
        )
    if len(plan.risks) > 20:
        lines.append("……另有 %d 条风险未展开" % (len(plan.risks) - 20))
    return "\n".join(lines)


def render_rollback_points(plan, base=0.0):  # type: (RotationPlan, float) -> str
    lines = []
    for point in plan.rollback_points:
        availability = "可用" if point.available else "不可用（前置门控未满足）"
        lines.append(
            "%s %s（%s，截止 %s）\n   动作：%s\n   影响：%s"
            % (
                point.point_id,
                point.name,
                availability,
                _fmt_time(point.deadline, base),
                point.action,
                point.impact,
            )
        )
    return "\n".join(lines)


def render_violations(plan, base=0.0):  # type: (RotationPlan, float) -> str
    if not plan.violations:
        return "解密覆盖模拟通过：任意在线节点在任意时刻均可定位正确的解密密钥。"
    lines = []
    for violation in plan.violations[:20]:
        lines.append(
            "- 节点 %s 在 %s：%s（票据签发于 %s）"
            % (
                violation.node_id,
                _fmt_time(violation.at, base),
                violation.reason,
                _fmt_time(violation.issued_at, base),
            )
        )
    if len(plan.violations) > 20:
        lines.append("……另有 %d 条违规未展开" % (len(plan.violations) - 20))
    return "\n".join(lines)


def render_report(config, plan):  # type: (RotationConfig, RotationPlan) -> str
    base = config.rotation_start_at
    if plan.fleet_ready:
        readiness = "是"
    else:
        readiness = "否（离线：%s）" % ", ".join(plan.offline_nodes)
    summary = (
        "轮换基准时间 T0=%s；在线节点就绪：%s；整体结论：%s"
        % (
            _fmt_time(config.rotation_start_at),
            readiness,
            "安全可执行" if plan.is_safe else "存在阻塞或兼容性缺口，禁止推进",
        )
    )
    sections = [
        "== 轮换时间表 ==",
        render_timetable(plan, base),
        "",
        "== 兼容风险 ==",
        render_risks(plan),
        "",
        "== 回滚点 ==",
        render_rollback_points(plan, base),
        "",
        "== 解密覆盖校验 ==",
        render_violations(plan, base),
    ]
    return summary + "\n\n" + "\n".join(sections)
