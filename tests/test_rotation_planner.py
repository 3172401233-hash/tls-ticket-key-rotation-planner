import unittest

from tls_ticket_rotation.model import (
    NodeReport,
    Phase,
    PhaseStatus,
    RiskLevel,
    RotationConfig,
)
from tls_ticket_rotation.planner import build_plan
from tls_ticket_rotation.report import render_report


T0 = 1_000_000.0
MAX_LIFE = 7200.0


def make_reports(count, spread=120.0):
    return [
        NodeReport(
            node_id="node-%03d" % index,
            effective_at=T0 + 10.0 + (index % 5) * spread / 5.0,
            last_seen_at=T0 + 200.0,
        )
        for index in range(count)
    ]


def healthy_config(**overrides):
    config = RotationConfig(
        node_reports=make_reports(8),
        ticket_age=1800.0,
        recovered_traffic_ratio=0.98,
        unknown_key_ratio=0.001,
        max_ticket_lifetime=MAX_LIFE,
        destroy_at=T0 + MAX_LIFE * 3,
        rotation_start_at=T0,
        clock_skew_margin=30.0,
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def event(plan, phase):
    matches = [item for item in plan.timetable if item.phase == phase]
    assert len(matches) == 1
    return matches[0]


class HappyPathTest(unittest.TestCase):
    def test_full_fleet_ack_produces_safe_plan(self):
        config = healthy_config()
        plan = build_plan(config)

        self.assertTrue(plan.fleet_ready)
        self.assertTrue(plan.is_safe)
        self.assertEqual(plan.offline_nodes, [])
        self.assertEqual(plan.violations, [])
        self.assertEqual(
            event(plan, Phase.DISTRIBUTE).status, PhaseStatus.PENDING
        )

        self.assertEqual(plan.issue_new_at, plan.distribution_done_at)
        self.assertEqual(
            plan.safe_stop_decrypt_at,
            plan.issue_new_at + MAX_LIFE + 30.0,
        )
        self.assertEqual(plan.safe_destroy_at, plan.safe_stop_decrypt_at)
        self.assertEqual(
            plan.practical_stop_decrypt_at,
            plan.issue_new_at + 1800.0 + 30.0,
        )

        phases = [item.phase for item in plan.timetable]
        self.assertEqual(
            phases,
            [
                Phase.DISTRIBUTE,
                Phase.DECRYPT_NEW,
                Phase.ISSUE_NEW,
                Phase.STOP_DECRYPT_OLD,
                Phase.DESTROY_OLD,
            ],
        )
        for point in plan.rollback_points:
            self.assertTrue(point.available)

    def test_now_drives_phase_status_without_marking_rotation_complete(self):
        config = healthy_config(now=T0 + 200.0)
        plan = build_plan(config)
        self.assertEqual(
            event(plan, Phase.DISTRIBUTE).status, PhaseStatus.COMPLETE
        )
        self.assertEqual(
            event(plan, Phase.DECRYPT_NEW).status, PhaseStatus.COMPLETE
        )
        self.assertEqual(
            event(plan, Phase.ISSUE_NEW).status, PhaseStatus.COMPLETE
        )
        self.assertEqual(
            event(plan, Phase.STOP_DECRYPT_OLD).status, PhaseStatus.PENDING
        )


class DelayedAndOfflineInstanceTest(unittest.TestCase):
    def test_multi_instance_delay_does_not_block_but_is_flagged(self):
        reports = [
            NodeReport(
                node_id="node-%03d" % index,
                effective_at=T0 + 10.0 + index,
                last_seen_at=T0 + 200.0,
            )
            for index in range(20)
        ]
        reports.append(
            NodeReport("node-late-1", T0 + 900.0, T0 + 900.0)
        )
        reports.append(
            NodeReport("node-late-2", T0 + 1200.0, T0 + 1200.0)
        )
        config = healthy_config(node_reports=reports, offline_grace=60.0)
        plan = build_plan(config)

        self.assertTrue(plan.fleet_ready)
        self.assertEqual(plan.late_nodes, ["node-late-1", "node-late-2"])
        self.assertEqual(plan.distribution_done_at, T0 + 1200.0)
        self.assertTrue(
            any(risk.code == "node_late_effective" for risk in plan.risks)
        )

    def test_offline_instance_blocks_every_unsafe_phase(self):
        reports = make_reports(6)
        reports[3] = NodeReport(
            node_id="node-003", effective_at=None, last_seen_at=T0 + 5.0
        )
        config = healthy_config(node_reports=reports, now=T0 + 500.0)
        plan = build_plan(config)

        self.assertFalse(plan.fleet_ready)
        self.assertFalse(plan.is_safe)
        self.assertEqual(plan.offline_nodes, ["node-003"])
        self.assertEqual(
            event(plan, Phase.DISTRIBUTE).status, PhaseStatus.IN_PROGRESS
        )
        for phase in (
            Phase.DECRYPT_NEW,
            Phase.ISSUE_NEW,
            Phase.STOP_DECRYPT_OLD,
            Phase.DESTROY_OLD,
        ):
            self.assertEqual(
                event(plan, phase).status,
                PhaseStatus.BLOCKED,
                msg=phase,
            )
        self.assertIsNone(plan.issue_new_at)
        self.assertTrue(
            any(
                risk.level == RiskLevel.CRITICAL
                and risk.code == "node_not_acked"
                for risk in plan.risks
            )
        )

    def test_all_instances_offline_blocks_distribution(self):
        reports = [
            NodeReport(node_id="node-%d" % i, effective_at=None)
            for i in range(3)
        ]
        config = healthy_config(node_reports=reports)
        plan = build_plan(config)
        self.assertEqual(
            event(plan, Phase.DISTRIBUTE).status, PhaseStatus.BLOCKED
        )
        self.assertFalse(plan.fleet_ready)

    def test_retired_node_is_excluded_from_gate(self):
        reports = make_reports(4)
        reports.append(
            NodeReport(node_id="drained-001", effective_at=None)
        )
        config = healthy_config(
            node_reports=reports, retired_node_ids=("drained-001",)
        )
        plan = build_plan(config)
        self.assertTrue(plan.fleet_ready)
        self.assertNotIn("drained-001", plan.offline_nodes)


class EarlyDestroyTest(unittest.TestCase):
    def test_old_key_destroyed_before_safe_horizon_is_critical(self):
        config = healthy_config(destroy_at=T0 + 600.0)
        plan = build_plan(config)

        self.assertFalse(plan.is_safe)
        critical = [
            risk
            for risk in plan.risks
            if risk.code == "old_key_destroyed_early"
        ]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0].level, RiskLevel.CRITICAL)

        self.assertEqual(
            event(plan, Phase.STOP_DECRYPT_OLD).status, PhaseStatus.BLOCKED
        )
        self.assertEqual(
            event(plan, Phase.DESTROY_OLD).status, PhaseStatus.BLOCKED
        )
        rb3 = plan.rollback_points[-1]
        self.assertEqual(rb3.point_id, "RB3")
        self.assertFalse(rb3.available)

        self.assertTrue(plan.violations)
        self.assertTrue(
            all(v.ticket_generation == "old" for v in plan.violations)
        )
        self.assertTrue(
            all("销毁" in v.reason for v in plan.violations)
        )

    def test_destroy_exactly_at_safe_time_is_allowed(self):
        config = healthy_config()
        plan = build_plan(config)
        exact_config = healthy_config(destroy_at=plan.safe_destroy_at)
        exact_plan = build_plan(exact_config)
        self.assertTrue(exact_plan.is_safe)
        self.assertEqual(exact_plan.violations, [])


class MetricGateTest(unittest.TestCase):
    def test_unknown_key_ratio_blocks_issue_only(self):
        config = healthy_config(unknown_key_ratio=0.05)
        plan = build_plan(config)
        self.assertEqual(
            event(plan, Phase.DECRYPT_NEW).status, PhaseStatus.PENDING
        )
        self.assertEqual(
            event(plan, Phase.ISSUE_NEW).status, PhaseStatus.BLOCKED
        )
        self.assertFalse(plan.is_safe)

    def test_low_recovery_ratio_blocks_issue(self):
        config = healthy_config(recovered_traffic_ratio=0.80)
        plan = build_plan(config)
        self.assertEqual(
            event(plan, Phase.ISSUE_NEW).status, PhaseStatus.BLOCKED
        )
        self.assertTrue(
            any(risk.code == "recovery_ratio_low" for risk in plan.risks)
        )


class CoverageTest(unittest.TestCase):
    def test_old_ticket_remains_decryptable_until_expiry(self):
        config = healthy_config()
        plan = build_plan(config)
        self.assertEqual(plan.violations, [])

    def test_ticket_age_above_lifetime_is_clamped_and_flagged(self):
        config = healthy_config(ticket_age=MAX_LIFE + 500.0)
        plan = build_plan(config)
        self.assertEqual(
            plan.practical_stop_decrypt_at,
            plan.issue_new_at + MAX_LIFE + 30.0,
        )
        self.assertTrue(
            any(
                risk.code == "ticket_age_exceeds_lifetime"
                and risk.level == RiskLevel.HIGH
                for risk in plan.risks
            )
        )

    def test_delayed_return_node_still_covered_when_old_key_kept(self):
        reports = make_reports(4)
        reports.append(
            NodeReport(
                node_id="slow-001",
                effective_at=T0 + 400.0,
                last_seen_at=T0 + 400.0,
            )
        )
        config = healthy_config(node_reports=reports)
        plan = build_plan(config)
        self.assertTrue(plan.fleet_ready)
        self.assertEqual(plan.violations, [])


class ValidationAndReportTest(unittest.TestCase):
    def test_invalid_inputs_raise(self):
        with self.assertRaises(ValueError):
            build_plan(healthy_config(max_ticket_lifetime=0))
        with self.assertRaises(ValueError):
            build_plan(healthy_config(unknown_key_ratio=1.5))
        with self.assertRaises(ValueError):
            build_plan(
                healthy_config(retired_node_ids=("ghost-node",))
            )

    def test_report_contains_all_sections(self):
        plan = build_plan(healthy_config())
        text = render_report(healthy_config(), plan)
        for section in (
            "轮换时间表",
            "兼容风险",
            "回滚点",
            "解密覆盖校验",
            "分发新密钥",
            "RB1",
        ):
            self.assertIn(section, text)


if __name__ == "__main__":
    unittest.main()
