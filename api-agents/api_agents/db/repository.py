"""Repository layer for persisting and analyzing 10-minute vault snapshots in PostgreSQL."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from api_agents.db.models import SnapshotDeltaRecord, Vault, VaultSnapshotRecord


class SnapshotRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def register_vault(
        self,
        vault_address: str,
        chain_id: int = 1,
        label: Optional[str] = None,
        threshold: int = 1,
        emergency_recovery_vault: Optional[str] = None,
    ) -> Vault:
        """Register or update a monitored vault in PostgreSQL."""
        addr = vault_address.lower()
        stmt = select(Vault).where(Vault.vault_address == addr)
        result = await self.session.execute(stmt)
        vault = result.scalar_one_or_none()

        if vault is None:
            vault = Vault(
                vault_address=addr,
                chain_id=chain_id,
                label=label,
                threshold=threshold,
                emergency_recovery_vault=emergency_recovery_vault,
                is_active=True,
            )
            self.session.add(vault)
        else:
            if label is not None:
                vault.label = label
            vault.chain_id = chain_id
            vault.threshold = threshold
            if emergency_recovery_vault is not None:
                vault.emergency_recovery_vault = emergency_recovery_vault
            vault.is_active = True

        await self.session.commit()
        await self.session.refresh(vault)
        return vault

    async def get_active_vaults(self) -> List[Vault]:
        """Retrieve all active tracked vaults."""
        stmt = select(Vault).where(Vault.is_active == True)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def record_snapshot(
        self,
        vault_address: str,
        chain_id: int,
        eth_balance_wei: str,
        token_balances: Dict[str, str],
        master_copy: str,
        owners_hash: str,
        threshold: int,
        guard: str,
        codehash: str,
        block_number: int = 0,
        block_hash: str = "0x" + "0" * 64,
        revert_strikes_in_window: int = 0,
        is_dead_mans_locked: bool = False,
        snapshot_timestamp: Optional[datetime] = None,
        window_seconds: int = 600,
    ) -> Tuple[VaultSnapshotRecord, Optional[SnapshotDeltaRecord]]:
        """Record a 10-minute snapshot in PostgreSQL, compute state deltas,

        and flag any control slot mutations or anomalous drainage.
        """
        addr = vault_address.lower()
        now = snapshot_timestamp or datetime.now(timezone.utc)

        # 1. Ensure vault exists in registry
        vault_stmt = select(Vault).where(Vault.vault_address == addr)
        v_res = await self.session.execute(vault_stmt)
        vault = v_res.scalar_one_or_none()
        if not vault:
            vault = Vault(
                vault_address=addr,
                chain_id=chain_id,
                threshold=threshold,
                is_active=True,
                last_snapshot_at=now,
            )
            self.session.add(vault)
        else:
            vault.last_snapshot_at = now

        # 2. Find previous snapshot for delta calculation
        prev_stmt = (
            select(VaultSnapshotRecord)
            .where(VaultSnapshotRecord.vault_address == addr)
            .order_by(desc(VaultSnapshotRecord.snapshot_timestamp))
            .limit(1)
        )
        prev_res = await self.session.execute(prev_stmt)
        prev_snap = prev_res.scalar_one_or_none()

        # 3. Create current snapshot record
        curr_snap = VaultSnapshotRecord(
            vault_address=addr,
            chain_id=chain_id,
            block_number=block_number,
            block_hash=block_hash,
            eth_balance_wei=str(eth_balance_wei),
            token_balances={k.lower(): str(v) for k, v in token_balances.items()},
            master_copy=master_copy.lower(),
            owners_hash=owners_hash.lower(),
            threshold=threshold,
            guard=guard.lower(),
            codehash=codehash.lower(),
            revert_strikes_in_window=revert_strikes_in_window,
            is_dead_mans_locked=is_dead_mans_locked,
            snapshot_timestamp=now,
        )
        self.session.add(curr_snap)
        await self.session.flush()  # assign curr_snap.id

        # 4. Compute 10-minute delta if a previous snapshot exists
        delta_record: Optional[SnapshotDeltaRecord] = None
        if prev_snap is not None:
            # Native balance delta
            curr_eth = int(curr_snap.eth_balance_wei)
            prev_eth = int(prev_snap.eth_balance_wei)
            eth_delta = curr_eth - prev_eth

            # Token deltas
            token_deltas: Dict[str, str] = {}
            all_tokens = set(curr_snap.token_balances.keys()) | set(prev_snap.token_balances.keys())
            for t in all_tokens:
                c_val = int(curr_snap.token_balances.get(t, "0"))
                p_val = int(prev_snap.token_balances.get(t, "0"))
                token_deltas[t] = str(c_val - p_val)

            # Check for control slot mutations (critical WazirX/Bybit exploit vector)
            slots_mutated = (
                curr_snap.master_copy != prev_snap.master_copy
                or curr_snap.owners_hash != prev_snap.owners_hash
                or curr_snap.threshold != prev_snap.threshold
                or curr_snap.guard != prev_snap.guard
                or curr_snap.codehash != prev_snap.codehash
            )

            # Anomaly rules
            anomaly_reasons = []
            if slots_mutated:
                anomaly_reasons.append("CRITICAL: Control slots mutated between 10-minute snapshots")
            if curr_snap.revert_strikes_in_window >= 3:
                anomaly_reasons.append("DEAD_MANS_SWITCH: 3 consecutive guard reverts in 10-min window")
            if curr_snap.is_dead_mans_locked:
                anomaly_reasons.append("EMERGENCY_LOCK: Vault locked by dead-man's switch")

            is_anomaly = len(anomaly_reasons) > 0

            delta_record = SnapshotDeltaRecord(
                vault_address=addr,
                previous_snapshot_id=prev_snap.id,
                current_snapshot_id=curr_snap.id,
                window_seconds=window_seconds,
                eth_delta_wei=str(eth_delta),
                token_deltas=token_deltas,
                control_slots_mutated=slots_mutated,
                is_anomaly=is_anomaly,
                anomaly_reason=" | ".join(anomaly_reasons) if anomaly_reasons else None,
                computed_at=now,
            )
            self.session.add(delta_record)

        await self.session.commit()
        await self.session.refresh(curr_snap)
        if delta_record is not None:
            await self.session.refresh(delta_record)

        return curr_snap, delta_record

    async def get_snapshots(
        self, vault_address: str, limit: int = 50, offset: int = 0
    ) -> List[VaultSnapshotRecord]:
        """Fetch historical 10-minute snapshots for a vault."""
        stmt = (
            select(VaultSnapshotRecord)
            .where(VaultSnapshotRecord.vault_address == vault_address.lower())
            .order_by(desc(VaultSnapshotRecord.snapshot_timestamp))
            .limit(limit)
            .offset(offset)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_latest_snapshot(self, vault_address: str) -> Optional[VaultSnapshotRecord]:
        """Fetch the most recent snapshot for a vault."""
        stmt = (
            select(VaultSnapshotRecord)
            .where(VaultSnapshotRecord.vault_address == vault_address.lower())
            .order_by(desc(VaultSnapshotRecord.snapshot_timestamp))
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_deltas(
        self, vault_address: str, anomalies_only: bool = False, limit: int = 50
    ) -> List[SnapshotDeltaRecord]:
        """Fetch 10-minute delta comparisons and anomalies for a vault."""
        stmt = (
            select(SnapshotDeltaRecord)
            .where(SnapshotDeltaRecord.vault_address == vault_address.lower())
        )
        if anomalies_only:
            stmt = stmt.where(SnapshotDeltaRecord.is_anomaly == True)
        stmt = stmt.order_by(desc(SnapshotDeltaRecord.computed_at)).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_stats(self) -> Dict[str, Any]:
        """Get aggregate counts across the PostgreSQL snapshot database."""
        v_count = await self.session.scalar(select(func.count(Vault.vault_address)))
        s_count = await self.session.scalar(select(func.count(VaultSnapshotRecord.id)))
        d_count = await self.session.scalar(select(func.count(SnapshotDeltaRecord.id)))
        a_count = await self.session.scalar(
            select(func.count(SnapshotDeltaRecord.id)).where(SnapshotDeltaRecord.is_anomaly == True)
        )
        return {
            "total_vaults": v_count or 0,
            "total_snapshots": s_count or 0,
            "total_deltas": d_count or 0,
            "total_anomalies": a_count or 0,
        }
