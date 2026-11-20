from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Sequence


class Phase(Enum):
    DISTRIBUTE = "distribute"
    DECRYPT_NEW = "decrypt_new"
    ISSUE_NEW = "issue_new"
    STOP_DECRYPT_OLD = "stop_decrypt_old"
    DESTROY_OLD = "destroy_old"


PHASE_LABELS = {
    Phase.DISTRIBUTE: "分发新密钥",
    Phase.DECRYPT_NEW: "启用新密钥解密",
    Phase.ISSUE_NEW: "切换为新密钥签发",
    Phase.STOP_DECRYPT_OLD: "停止旧密钥解密",
    Phase.DESTROY_OLD: "销毁旧密钥",
}


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


RISK_LEVEL_LABELS = {
    RiskLevel.CRITICAL: "严重",
    RiskLevel.HIGH: "高",
    RiskLevel.MEDIUM: "中",
    RiskLevel.LOW: "低",
}

RISK_LEVEL_ORDER = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 3,
}


class PhaseStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    BLOCKED = "blocked"


PHASE_STATUS_LABELS = {
    PhaseStatus.PENDING: "待执行",
    PhaseStatus.IN_PROGRESS: "进行中",
    PhaseStatus.COMPLETE: "已完成",
    PhaseStatus.BLOCKED: "已阻塞",
}


@dataclass
class NodeReport:
    """单个入口节点的新密钥生效上报。

    effective_at 为 None 表示该实例从未确认新密钥生效（离线或延迟上线），
    last_seen_at 为最近一次心跳时间。
    """

    node_id: str
    effective_at: Optional[float] = None
    last_seen_at: Optional[float] = None


@dataclass
class RotationConfig:
    """轮换规划输入。

    时间单位均为秒级 epoch 时间戳（或与调用方一致的相对时间基准）。
    """

    node_reports: Sequence[NodeReport]
    ticket_age: float
    recovered_traffic_ratio: float
    unknown_key_ratio: float
    max_ticket_lifetime: float
    destroy_at: float
    rotation_start_at: float
    now: Optional[float] = None
    retired_node_ids: Sequence[str] = field(default_factory=tuple)
    offline_grace: float = 30.0
    decryption_hold: float = 0.0
    clock_skew_margin: float = 30.0
    max_unknown_key_ratio: float = 0.01
    min_recovered_traffic_ratio: float = 0.95


@dataclass
class Risk:
    level: RiskLevel
    code: str
    message: str
    mitigation: str


@dataclass
class PhaseEvent:
    phase: Phase
    planned_at: Optional[float]
    earliest_safe_at: Optional[float]
    gate: str
    status: PhaseStatus
    detail: str


@dataclass
class RollbackPoint:
    point_id: str
    name: str
    before_phase: Phase
    deadline: Optional[float]
    action: str
    impact: str
    available: bool


@dataclass
class CoverageViolation:
    node_id: str
    at: float
    ticket_generation: str
    issued_at: float
    reason: str


@dataclass
class RotationPlan:
    timetable: List[PhaseEvent]
    risks: List[Risk]
    rollback_points: List[RollbackPoint]
    violations: List[CoverageViolation]
    distribution_done_at: Optional[float]
    issue_new_at: Optional[float]
    practical_stop_decrypt_at: Optional[float]
    safe_stop_decrypt_at: Optional[float]
    safe_destroy_at: Optional[float]
    fleet_ready: bool
    offline_nodes: List[str]
    late_nodes: List[str]
    is_safe: bool
