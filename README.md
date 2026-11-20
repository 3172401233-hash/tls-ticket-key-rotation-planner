# tls-ticket-key-rotation-planner

面向 500+ 入口节点的 TLS 会话票据密钥（RFC 5077 / RFC 8446 ticket key）轮换规划器。
在分发、解密、签发、退役四个动作之间插入显式门控，保证任意时刻任意在线节点
都能定位到正确的解密密钥。

## 轮换阶段与门控

1. **分发新密钥（distribute）**：新密钥推送到全部在线节点的解密环，与旧密钥并存。
   门控：所有在线节点都上报 `effective_at`；`effective_at` 为空的离线/延迟实例
   会阻塞轮换，不会被静默忽略。确认永久摘流的节点可通过 `retired_node_ids` 排除。
2. **启用新密钥解密（decrypt_new）**：节点开始同时用新旧密钥解密，签发密钥不变。
3. **切换新密钥签发（issue_new）**：门控为全量分发完成、
   `unknown_key_ratio <= max_unknown_key_ratio`、
   `recovered_traffic_ratio >= min_recovered_traffic_ratio`。
4. **停止旧密钥解密（stop_decrypt_old）**：最早安全时间 =
   签发切换时间 + `max_ticket_lifetime` + 时钟裕量；
   观测票据年龄 `ticket_age` 给出可提前的实操时间，但安全结论以最长票据周期为准。
5. **销毁旧密钥（destroy_old）**：销毁时间早于安全时间会被标记为严重风险，
   覆盖模拟会逐条列出仍在生命周期内、将无法解密的旧票据。

## 输入

`RotationConfig` 的必填项（均为秒级时间戳或比率）：

| 字段 | 含义 |
| --- | --- |
| `node_reports` | 每个节点的 `NodeReport(node_id, effective_at, last_seen_at)`，`effective_at=None` 表示未确认生效 |
| `ticket_age` | 观测到的票据年龄（建议 P99），用于计算实操停用时间 |
| `recovered_traffic_ratio` | 票据恢复流量占比，低于门限则禁止切换签发 |
| `unknown_key_ratio` | 未知密钥率，高于门限则禁止切换签发 |
| `max_ticket_lifetime` | 票据最长生命周期，决定旧密钥强制保留窗口 |
| `destroy_at` | 计划销毁旧密钥的时间 |
| `rotation_start_at` | 轮换基准时间 T0，报告以 `T+偏移` 展示 |

可选：`now`（用于推导各阶段状态）、`retired_node_ids`、`offline_grace`、
`clock_skew_margin`、`decryption_hold` 及两个指标门限。

## 输出

- 时间表：五个阶段的计划时间、最早安全时间、状态与门控条件；
- 兼容风险：按严重/高/中/低排序，每条带缓解措施；
- 回滚点：RB1 签发切换前、RB2 旧密钥停用前、RB3 旧密钥销毁前；
- 解密覆盖校验：模拟票据签发与出示时间线，输出具体节点、时刻和失败原因。

## 使用

```python
from tls_ticket_rotation import NodeReport, RotationConfig, build_plan, render_report

config = RotationConfig(
    node_reports=[NodeReport("edge-1", effective_at=T0 + 30, last_seen_at=T0 + 60)],
    ticket_age=2400.0,
    recovered_traffic_ratio=0.98,
    unknown_key_ratio=0.001,
    max_ticket_lifetime=7200.0,
    destroy_at=T0 + 10800.0,
    rotation_start_at=T0,
)
plan = build_plan(config)
print(render_report(config, plan))
```

完整示例：`python examples/demo_rotation.py`

## 测试

```
python -m unittest
```

覆盖场景：全量就绪的安全轮换、多实例长尾延迟、离线实例阻塞、
退役节点排除、旧密钥提前销毁、指标门控、票据年龄越界裁剪与输入校验。
代码仅使用 Python 3.8.2 可用语法（`typing` 泛型、dataclass、枚举）。
