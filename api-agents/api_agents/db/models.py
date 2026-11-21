"""SQLAlchemy ORM models for 10-minute vault snapshots and state delta auditing.
Compatible with Cloud PostgreSQL (JSONB, BigInteger) and SQLite.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Vault(Base):
    __tablename__ = "vaults"

    vault_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    chain_id: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    label: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    emergency_recovery_vault: Mapped[Optional[str]] = mapped_column(String(42), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_snapshot_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vault_address": self.vault_address,
            "chain_id": self.chain_id,
            "label": self.label,
            "threshold": self.threshold,
            "emergency_recovery_vault": self.emergency_recovery_vault,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_snapshot_at": self.last_snapshot_at.isoformat() if self.last_snapshot_at else None,
        }


class VaultSnapshotRecord(Base):
    __tablename__ = "vault_snapshots"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    vault_address: Mapped[str] = mapped_column(String(42), index=True, nullable=False)
    chain_id: Mapped[int] = mapped_column(BigInteger, index=True, nullable=False, default=1)
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    block_hash: Mapped[str] = mapped_column(String(66), nullable=False, default="0x" + "0" * 64)

    # Balances
    eth_balance_wei: Mapped[str] = mapped_column(String(78), nullable=False, default="0")
    token_balances: Mapped[Dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)

    # Control Slots (Protected by VeroGuard)
    master_copy: Mapped[str] = mapped_column(String(42), nullable=False, default="0x" + "0" * 40)
    owners_hash: Mapped[str] = mapped_column(String(66), nullable=False, default="0x" + "0" * 64)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    guard: Mapped[str] = mapped_column(String(42), nullable=False, default="0x" + "0" * 40)
    codehash: Mapped[str] = mapped_column(String(66), nullable=False, default="0x" + "0" * 64)

    # Feature #37: Dead-Man's Switch Window status (10 min / 600s rolling window)
    revert_strikes_in_window: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_dead_mans_locked: Mapped[bool] = mapped_column(Boolean, default=False)

    snapshot_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vault_address": self.vault_address,
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "eth_balance_wei": self.eth_balance_wei,
            "token_balances": self.token_balances,
            "control_slots": {
                "master_copy": self.master_copy,
                "owners_hash": self.owners_hash,
                "threshold": self.threshold,
                "guard": self.guard,
                "codehash": self.codehash,
            },
            "revert_strikes_in_window": self.revert_strikes_in_window,
            "is_dead_mans_locked": self.is_dead_mans_locked,
            "snapshot_timestamp": self.snapshot_timestamp.isoformat() if self.snapshot_timestamp else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class SnapshotDeltaRecord(Base):
    __tablename__ = "snapshot_deltas"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    vault_address: Mapped[str] = mapped_column(String(42), index=True, nullable=False)
    previous_snapshot_id: Mapped[Optional[int]] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), nullable=True)
    current_snapshot_id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), nullable=False)

    window_seconds: Mapped[int] = mapped_column(Integer, default=600)  # standard 10-minute window
    eth_delta_wei: Mapped[str] = mapped_column(String(78), nullable=False, default="0")
    token_deltas: Mapped[Dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)

    control_slots_mutated: Mapped[bool] = mapped_column(Boolean, default=False)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    anomaly_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vault_address": self.vault_address,
            "previous_snapshot_id": self.previous_snapshot_id,
            "current_snapshot_id": self.current_snapshot_id,
            "window_seconds": self.window_seconds,
            "eth_delta_wei": self.eth_delta_wei,
            "token_deltas": self.token_deltas,
            "control_slots_mutated": self.control_slots_mutated,
            "is_anomaly": self.is_anomaly,
            "anomaly_reason": self.anomaly_reason,
            "computed_at": self.computed_at.isoformat() if self.computed_at else None,
        }
