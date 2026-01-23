#!/usr/bin/env python3
"""
TrapNinja Test Suite - Core Types Tests

Tests for trapninja.core.types module.

Assumptions:
- Dataclasses should be properly defined with correct fields
- Type aliases should be importable and usable
- Enums should have correct values
- Dataclass methods (to_dict, properties) should work correctly
- PacketData should be hashable and immutable (frozen)

Author: TrapNinja Team
"""

import pytest
import time
from dataclasses import FrozenInstanceError


class TestTypeAliases:
    """Tests for type alias definitions."""

    def test_destination_alias(self):
        """Test Destination type alias is usable."""
        from trapninja.core.types import Destination
        
        # Should work as a tuple[str, int] annotation
        dest: Destination = ("192.168.1.100", 162)
        assert dest[0] == "192.168.1.100"
        assert dest[1] == 162

    def test_destination_list_alias(self):
        """Test DestinationList type alias is usable."""
        from trapninja.core.types import DestinationList
        
        destinations: DestinationList = [
            ("192.168.1.100", 162),
            ("192.168.1.101", 162),
        ]
        assert len(destinations) == 2

    def test_oid_alias(self):
        """Test OID type alias is string."""
        from trapninja.core.types import OID
        
        oid: OID = "1.3.6.1.4.1.8072.2.3.0.1"
        assert isinstance(oid, str)

    def test_ip_address_alias(self):
        """Test IPAddress type alias is string."""
        from trapninja.core.types import IPAddress
        
        ip: IPAddress = "192.168.1.100"
        assert isinstance(ip, str)


class TestPacketData:
    """Tests for PacketData dataclass."""

    def test_basic_creation(self):
        """Test basic PacketData creation."""
        from trapninja.core.types import PacketData
        
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_port=162,
            payload=b"\x30\x05\x02\x01\x00"
        )
        
        assert packet.src_ip == "192.168.1.100"
        assert packet.dst_port == 162
        assert packet.payload == b"\x30\x05\x02\x01\x00"

    def test_timestamp_default(self):
        """Test timestamp has a default value."""
        from trapninja.core.types import PacketData
        
        before = time.time()
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_port=162,
            payload=b"test"
        )
        after = time.time()
        
        # Timestamp should be set automatically
        assert packet.timestamp is not None
        assert before <= packet.timestamp <= after

    def test_explicit_timestamp(self):
        """Test explicit timestamp is used."""
        from trapninja.core.types import PacketData
        
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_port=162,
            payload=b"test",
            timestamp=1704067200.0
        )
        
        assert packet.timestamp == 1704067200.0

    def test_is_frozen(self):
        """Test PacketData is immutable (frozen)."""
        from trapninja.core.types import PacketData
        
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_port=162,
            payload=b"test",
            timestamp=1704067200.0
        )
        
        with pytest.raises(FrozenInstanceError):
            packet.src_ip = "10.0.0.1"

    def test_is_hashable(self):
        """Test PacketData is hashable."""
        from trapninja.core.types import PacketData
        
        packet = PacketData(
            src_ip="192.168.1.100",
            dst_port=162,
            payload=b"test",
            timestamp=1704067200.0
        )
        
        # Should be hashable
        hash_value = hash(packet)
        assert isinstance(hash_value, int)

    def test_same_data_same_hash(self):
        """Test identical packets have same hash."""
        from trapninja.core.types import PacketData
        
        packet1 = PacketData(
            src_ip="192.168.1.100",
            dst_port=162,
            payload=b"test",
            timestamp=1704067200.0
        )
        packet2 = PacketData(
            src_ip="192.168.1.100",
            dst_port=162,
            payload=b"test",
            timestamp=1704067200.0
        )
        
        assert hash(packet1) == hash(packet2)

    def test_usable_in_set(self):
        """Test PacketData can be used in sets."""
        from trapninja.core.types import PacketData
        
        packet1 = PacketData(
            src_ip="192.168.1.100",
            dst_port=162,
            payload=b"test",
            timestamp=1704067200.0
        )
        packet2 = PacketData(
            src_ip="192.168.1.101",
            dst_port=162,
            payload=b"test",
            timestamp=1704067200.0
        )
        
        packet_set = {packet1, packet2}
        assert len(packet_set) == 2


class TestParsedTrap:
    """Tests for ParsedTrap dataclass."""

    def test_basic_creation(self):
        """Test basic ParsedTrap creation."""
        from trapninja.core.types import ParsedTrap
        
        trap = ParsedTrap(
            version="v2c",
            source_ip="192.168.1.100",
            trap_oid="1.3.6.1.4.1.8072.2.3.0.1",
            enterprise_oid=None,
            varbinds={"1.3.6.1.2.1.1.3.0": "12345"}
        )
        
        assert trap.version == "v2c"
        assert trap.source_ip == "192.168.1.100"
        assert trap.trap_oid == "1.3.6.1.4.1.8072.2.3.0.1"
        assert trap.enterprise_oid is None
        assert "1.3.6.1.2.1.1.3.0" in trap.varbinds

    def test_optional_fields(self):
        """Test optional fields have correct defaults."""
        from trapninja.core.types import ParsedTrap
        
        trap = ParsedTrap(
            version="v2c",
            source_ip="192.168.1.100",
            trap_oid=None,
            enterprise_oid=None,
            varbinds={}
        )
        
        assert trap.community is None
        assert trap.security_name is None
        assert trap.raw_payload is None

    def test_with_all_fields(self):
        """Test creation with all fields."""
        from trapninja.core.types import ParsedTrap
        
        trap = ParsedTrap(
            version="v3",
            source_ip="192.168.1.100",
            trap_oid="1.3.6.1.4.1.8072.2.3.0.1",
            enterprise_oid="1.3.6.1.4.1.8072",
            varbinds={"oid1": "value1"},
            community=None,
            security_name="admin",
            raw_payload=b"raw_data"
        )
        
        assert trap.security_name == "admin"
        assert trap.raw_payload == b"raw_data"


class TestForwardingResult:
    """Tests for ForwardingResult dataclass."""

    def test_successful_result(self):
        """Test successful forwarding result."""
        from trapninja.core.types import ForwardingResult
        
        result = ForwardingResult(
            success=True,
            destinations_reached=3,
            destinations_failed=0
        )
        
        assert result.success is True
        assert result.destinations_reached == 3
        assert result.destinations_failed == 0
        assert result.error_message is None

    def test_failed_result(self):
        """Test failed forwarding result."""
        from trapninja.core.types import ForwardingResult
        
        result = ForwardingResult(
            success=False,
            destinations_reached=1,
            destinations_failed=2,
            error_message="Connection refused"
        )
        
        assert result.success is False
        assert result.destinations_failed == 2
        assert result.error_message == "Connection refused"

    def test_forwarding_time(self):
        """Test forwarding time field."""
        from trapninja.core.types import ForwardingResult
        
        result = ForwardingResult(
            success=True,
            destinations_reached=1,
            destinations_failed=0,
            forwarding_time_ms=2.5
        )
        
        assert result.forwarding_time_ms == 2.5


class TestRedirectionRule:
    """Tests for RedirectionRule dataclass."""

    def test_ip_rule(self):
        """Test IP-based redirection rule."""
        from trapninja.core.types import RedirectionRule
        
        rule = RedirectionRule(
            rule_type="ip",
            pattern="192.168.10.0/24",
            tag="security"
        )
        
        assert rule.rule_type == "ip"
        assert rule.pattern == "192.168.10.0/24"
        assert rule.tag == "security"
        assert rule.enabled is True  # Default

    def test_oid_rule(self):
        """Test OID-based redirection rule."""
        from trapninja.core.types import RedirectionRule
        
        rule = RedirectionRule(
            rule_type="oid",
            pattern="1.3.6.1.4.1.8072.*",
            tag="netsnmp",
            enabled=False
        )
        
        assert rule.rule_type == "oid"
        assert rule.enabled is False


class TestRedirectionMatch:
    """Tests for RedirectionMatch dataclass."""

    def test_no_redirection(self):
        """Test non-redirected match."""
        from trapninja.core.types import RedirectionMatch
        
        match = RedirectionMatch(
            is_redirected=False,
            destinations=[]
        )
        
        assert match.is_redirected is False
        assert match.destinations == []
        assert match.tag is None
        assert match.matched_by is None

    def test_ip_redirect(self):
        """Test IP-based redirection match."""
        from trapninja.core.types import RedirectionMatch
        
        match = RedirectionMatch(
            is_redirected=True,
            destinations=[("192.168.1.100", 1362)],
            tag="security",
            matched_by="ip"
        )
        
        assert match.is_redirected is True
        assert len(match.destinations) == 1
        assert match.tag == "security"
        assert match.matched_by == "ip"


class TestFilterAction:
    """Tests for FilterAction enum."""

    def test_filter_actions_exist(self):
        """Test all filter actions are defined."""
        from trapninja.core.types import FilterAction
        
        assert hasattr(FilterAction, "ALLOW")
        assert hasattr(FilterAction, "BLOCK")
        assert hasattr(FilterAction, "REDIRECT")

    def test_filter_actions_are_distinct(self):
        """Test filter actions have distinct values."""
        from trapninja.core.types import FilterAction
        
        actions = [FilterAction.ALLOW, FilterAction.BLOCK, FilterAction.REDIRECT]
        assert len(actions) == len(set(actions))


class TestFilterResult:
    """Tests for FilterResult dataclass."""

    def test_allow_result(self):
        """Test allow filter result."""
        from trapninja.core.types import FilterResult, FilterAction
        
        result = FilterResult(action=FilterAction.ALLOW)
        
        assert result.action == FilterAction.ALLOW
        assert result.reason is None
        assert result.redirect_tag is None

    def test_block_result(self):
        """Test block filter result with reason."""
        from trapninja.core.types import FilterResult, FilterAction
        
        result = FilterResult(
            action=FilterAction.BLOCK,
            reason="IP in blocklist"
        )
        
        assert result.action == FilterAction.BLOCK
        assert result.reason == "IP in blocklist"

    def test_redirect_result(self):
        """Test redirect filter result."""
        from trapninja.core.types import FilterResult, FilterAction
        
        result = FilterResult(
            action=FilterAction.REDIRECT,
            redirect_tag="security"
        )
        
        assert result.action == FilterAction.REDIRECT
        assert result.redirect_tag == "security"


class TestProcessingStats:
    """Tests for ProcessingStats dataclass."""

    def test_default_values(self):
        """Test default statistics are zero."""
        from trapninja.core.types import ProcessingStats
        
        stats = ProcessingStats()
        
        assert stats.packets_received == 0
        assert stats.packets_forwarded == 0
        assert stats.packets_blocked == 0
        assert stats.packets_redirected == 0
        assert stats.packets_dropped == 0
        assert stats.packets_errors == 0
        assert stats.fast_path_hits == 0
        assert stats.slow_path_hits == 0
        assert stats.queue_full_events == 0
        assert stats.max_queue_depth == 0

    def test_to_dict(self):
        """Test conversion to dictionary."""
        from trapninja.core.types import ProcessingStats
        
        stats = ProcessingStats(
            packets_received=100,
            packets_forwarded=90,
            packets_blocked=5,
            packets_redirected=3,
            packets_dropped=2
        )
        
        result = stats.to_dict()
        
        assert isinstance(result, dict)
        assert result["packets_received"] == 100
        assert result["packets_forwarded"] == 90
        assert result["packets_blocked"] == 5

    def test_fast_path_ratio_calculation(self):
        """Test fast path ratio property."""
        from trapninja.core.types import ProcessingStats
        
        stats = ProcessingStats(
            fast_path_hits=80,
            slow_path_hits=20
        )
        
        assert stats.fast_path_ratio == 80.0

    def test_fast_path_ratio_zero_division(self):
        """Test fast path ratio with no packets."""
        from trapninja.core.types import ProcessingStats
        
        stats = ProcessingStats()
        
        # Should not raise, should return 0
        assert stats.fast_path_ratio == 0.0


class TestQueueStats:
    """Tests for QueueStats dataclass."""

    def test_default_values(self):
        """Test default queue statistics."""
        from trapninja.core.types import QueueStats
        
        stats = QueueStats()
        
        assert stats.current_depth == 0
        assert stats.max_depth == 0
        assert stats.capacity == 0
        assert stats.total_queued == 0
        assert stats.total_dropped == 0

    def test_utilization_calculation(self):
        """Test queue utilization property."""
        from trapninja.core.types import QueueStats
        
        stats = QueueStats(
            current_depth=500,
            capacity=1000
        )
        
        assert stats.utilization == 0.5

    def test_utilization_zero_capacity(self):
        """Test utilization with zero capacity."""
        from trapninja.core.types import QueueStats
        
        stats = QueueStats(capacity=0)
        
        # Should not raise, should return 0
        assert stats.utilization == 0.0


class TestHAStateEnum:
    """Tests for HAStateEnum."""

    def test_all_states_defined(self):
        """Test all HA states are defined."""
        from trapninja.core.types import HAStateEnum
        
        expected_states = [
            "INITIALIZING", "PRIMARY", "SECONDARY",
            "STANDALONE", "FAILOVER", "SPLIT_BRAIN", "ERROR"
        ]
        
        for state_name in expected_states:
            assert hasattr(HAStateEnum, state_name)

    def test_state_values(self):
        """Test state enum values are lowercase strings."""
        from trapninja.core.types import HAStateEnum
        
        assert HAStateEnum.INITIALIZING.value == "initializing"
        assert HAStateEnum.PRIMARY.value == "primary"
        assert HAStateEnum.SECONDARY.value == "secondary"
        assert HAStateEnum.STANDALONE.value == "standalone"
        assert HAStateEnum.FAILOVER.value == "failover"
        assert HAStateEnum.SPLIT_BRAIN.value == "split_brain"
        assert HAStateEnum.ERROR.value == "error"


class TestHAStatus:
    """Tests for HAStatus dataclass."""

    def test_basic_creation(self):
        """Test basic HAStatus creation."""
        from trapninja.core.types import HAStatus, HAStateEnum
        
        status = HAStatus(
            instance_id="node-1",
            state=HAStateEnum.PRIMARY,
            is_forwarding=True,
            uptime=3600.0,
            priority=100,
            peer_connected=True,
            peer_state=HAStateEnum.SECONDARY,
            peer_priority=90,
            peer_uptime=3500.0,
            split_brain_detected=False,
            manual_override=False
        )
        
        assert status.instance_id == "node-1"
        assert status.state == HAStateEnum.PRIMARY
        assert status.is_forwarding is True

    def test_to_dict(self):
        """Test conversion to dictionary."""
        from trapninja.core.types import HAStatus, HAStateEnum
        
        status = HAStatus(
            instance_id="node-1",
            state=HAStateEnum.PRIMARY,
            is_forwarding=True,
            uptime=3600.0,
            priority=100,
            peer_connected=True,
            peer_state=HAStateEnum.SECONDARY,
            peer_priority=90,
            peer_uptime=3500.0,
            split_brain_detected=False,
            manual_override=False
        )
        
        result = status.to_dict()
        
        assert isinstance(result, dict)
        assert result["instance_id"] == "node-1"
        assert result["state"] == "primary"  # Enum value
        assert result["peer_state"] == "secondary"

    def test_to_dict_with_none_peer_state(self):
        """Test to_dict handles None peer_state."""
        from trapninja.core.types import HAStatus, HAStateEnum
        
        status = HAStatus(
            instance_id="node-1",
            state=HAStateEnum.STANDALONE,
            is_forwarding=True,
            uptime=3600.0,
            priority=100,
            peer_connected=False,
            peer_state=None,
            peer_priority=0,
            peer_uptime=0.0,
            split_brain_detected=False,
            manual_override=False
        )
        
        result = status.to_dict()
        
        assert result["peer_state"] is None


class TestServiceConfig:
    """Tests for ServiceConfig dataclass."""

    def test_default_values(self):
        """Test default service configuration."""
        from trapninja.core.types import ServiceConfig
        
        config = ServiceConfig()
        
        assert config.interface == "ens192"
        assert config.listen_ports == [162]
        assert config.destinations == []
        assert config.capture_mode == "auto"
        assert config.debug is False

    def test_custom_values(self):
        """Test custom service configuration."""
        from trapninja.core.types import ServiceConfig
        
        config = ServiceConfig(
            interface="eth0",
            listen_ports=[162, 1162],
            destinations=[("192.168.1.100", 162)],
            capture_mode="sniff",
            debug=True
        )
        
        assert config.interface == "eth0"
        assert len(config.listen_ports) == 2
        assert config.debug is True


class TestSNMPv3Credentials:
    """Tests for SNMPv3Credentials dataclass."""

    def test_minimal_credentials(self):
        """Test minimal SNMPv3 credentials (noAuthNoPriv)."""
        from trapninja.core.types import SNMPv3Credentials
        
        creds = SNMPv3Credentials(username="admin")
        
        assert creds.username == "admin"
        assert creds.auth_protocol == "none"
        assert creds.auth_key is None
        assert creds.priv_protocol == "none"
        assert creds.priv_key is None
        assert creds.engine_id is None

    def test_auth_credentials(self):
        """Test authNoPriv credentials."""
        from trapninja.core.types import SNMPv3Credentials
        
        creds = SNMPv3Credentials(
            username="admin",
            auth_protocol="SHA",
            auth_key="authkey123"
        )
        
        assert creds.auth_protocol == "SHA"
        assert creds.auth_key == "authkey123"

    def test_full_credentials(self):
        """Test authPriv credentials."""
        from trapninja.core.types import SNMPv3Credentials
        
        creds = SNMPv3Credentials(
            username="admin",
            auth_protocol="SHA256",
            auth_key="authkey123",
            priv_protocol="AES128",
            priv_key="privkey456",
            engine_id="0x80001234"
        )
        
        assert creds.auth_protocol == "SHA256"
        assert creds.priv_protocol == "AES128"
        assert creds.engine_id == "0x80001234"
