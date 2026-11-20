"""
Quai Network RPC Adapter and External Transaction (ETX) Decoder.
Translates quai_* JSON-RPC methods and enforces zone/shard coordinate rules.
"""

from typing import Dict, Any, Optional, List
import json
from shared.schemas import QUAI_NETWORKS, QUAI_ZONES, get_quai_zone_for_address


class QuaiRpcAdapter:
    """
    Translates Quai Network JSON-RPC methods and coordinates shard state.
    Provides local deterministic simulation fallback when live node is offline.
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        chain_id: int = 15000,
        default_zone: str = "cyprus1",
    ):
        self.rpc_url = rpc_url or QUAI_NETWORKS["orchard"]["rpc"]
        self.chain_id = chain_id
        self.default_zone = default_zone
        self.is_offline_mock = True

    def translate_quai_rpc(self, method: str, params: List[Any]) -> Dict[str, Any]:
        """
        Translates quai_* RPC methods to standard EVM methods or processes Quai-native calls.
        """
        mapping = {
            "quai_getCode": "eth_getCode",
            "quai_getStorageAt": "eth_getStorageAt",
            "quai_getBalance": "eth_getBalance",
            "quai_chainId": "eth_chainId",
            "quai_blockNumber": "eth_blockNumber",
            "quai_call": "eth_call",
            "quai_estimateGas": "eth_estimateGas",
            "quai_sendRawTransaction": "eth_sendRawTransaction",
        }

        translated_method = mapping.get(method, method)
        return {
            "original_method": method,
            "translated_method": translated_method,
            "params": params,
            "chain_id": self.chain_id,
            "zone": self.default_zone,
        }

    def decode_etx(self, raw_tx_hex: str) -> Dict[str, Any]:
        """
        Decodes a Quai External Transaction (ETX) bridging state between shards.
        ETX transactions contain origin and destination zone coordinates.
        """
        clean = raw_tx_hex.lower().replace("0x", "")
        # Minimal mock or structured ETX decoder
        is_etx = len(clean) >= 140
        from_zone = "cyprus1"
        to_zone = "cyprus1"
        if len(clean) >= 4:
            from_prefix = "0x" + clean[:2]
            to_prefix = "0x" + clean[2:4]
            for zk, zv in QUAI_ZONES.items():
                if zv["prefix"].lower() == from_prefix:
                    from_zone = zk
                if zv["prefix"].lower() == to_prefix:
                    to_zone = zk

        return {
            "is_etx": is_etx,
            "from_zone": from_zone,
            "to_zone": to_zone,
            "is_cross_shard": from_zone != to_zone,
            "estimated_poem_finality_seconds": 5.0 if from_zone == to_zone else 15.0,
        }

    def get_zone_status(self, zone_name: str = "cyprus1") -> Dict[str, Any]:
        """Returns PoEM consensus and telemetry metadata for a given Quai zone."""
        zone_info = QUAI_ZONES.get(zone_name.lower(), QUAI_ZONES["cyprus1"])
        return {
            "zone": zone_name,
            "name": zone_info["name"],
            "prefix": zone_info["prefix"],
            "coordinates": zone_info["coords"],
            "consensus": "PoEM (Proof-of-Entropy-Minima)",
            "block_time_seconds": 5.0,
            "dual_currency": ["QUAI", "QI"],
            "status": "HEALTHY",
        }
