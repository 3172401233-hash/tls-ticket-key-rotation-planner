"""520 个入口节点的轮换规划演示。

运行：python examples/demo_rotation.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tls_ticket_rotation import (
    NodeReport,
    RotationConfig,
    build_plan,
    render_report,
)


T0 = 1_700_000_000.0


def main():
    reports = [
        NodeReport(
            node_id="edge-%04d" % index,
            effective_at=T0 + 5.0 + (index % 17) * 7.0,
            last_seen_at=T0 + 300.0,
        )
        for index in range(520)
    ]
    reports[77].effective_at = T0 + 1500.0
    reports[401].effective_at = T0 + 1800.0

    config = RotationConfig(
        node_reports=reports,
        ticket_age=2400.0,
        recovered_traffic_ratio=0.972,
        unknown_key_ratio=0.004,
        max_ticket_lifetime=7200.0,
        destroy_at=T0 + 10800.0,
        rotation_start_at=T0,
        now=T0 + 600.0,
    )
    plan = build_plan(config)
    print(render_report(config, plan))


if __name__ == "__main__":
    main()
