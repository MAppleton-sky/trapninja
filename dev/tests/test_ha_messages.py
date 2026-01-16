#!/usr/bin/env python3
"""
TrapNinja Test Suite - HA Messages Tests

Tests for trapninja.ha.messages module - HA protocol messages.

Author: TrapNinja Team
"""

import time
import json
import pytest
from unittest.mock import patch, MagicMock


class TestHAMessageTypeEnum:
    """Tests for HAMessageType enum."""

    def test_all_message_types_exist(self):
        """Test all expected message types exist."""
        from trapninja.ha.messages import HAMessageType
        
        assert HAMessageType.HEARTBEAT
        assert HAMessageType.HEARTBEAT_ACK
        assert HAMessageType.CLAIM_PRIMARY
        assert HAMessageType.YIELD_PRIMARY
        assert HAMessageType.FORCE_SECONDARY
        assert HAMessageType.STATUS_REQUEST
        assert HAMessageType.STATUS_RESPONSE
        assert HAMessageType.SHUTDOWN

    def test_str_representation(self):
        """Test string representation."""
        from trapninja.ha.messages import HAMessageType
        
        assert str(HAMessageType.HEARTBEAT) == "heartbeat"
        assert str(HAMessageType.CLAIM_PRIMARY) == "claim_primary"


class TestHAMessageTypeProperties:
    """Tests for HAMessageType properties."""

    def test_requires_response_heartbeat(self):
        """Test HEARTBEAT requires response."""
        from trapninja.ha.messages import HAMessageType
        
        assert HAMessageType.HEARTBEAT.requires_response is True

    def test_requires_response_status_request(self):
        """Test STATUS_REQUEST requires response."""
        from trapninja.ha.messages import HAMessageType
        
        assert HAMessageType.STATUS_REQUEST.requires_response is True

    def test_requires_response_shutdown(self):
        """Test SHUTDOWN does not require response."""
        from trapninja.ha.messages import HAMessageType
        
        assert HAMessageType.SHUTDOWN.requires_response is False

    def test_is_command_claim_primary(self):
        """Test CLAIM_PRIMARY is a command."""
        from trapninja.ha.messages import HAMessageType
        
        assert HAMessageType.CLAIM_PRIMARY.is_command is True

    def test_is_command_force_secondary(self):
        """Test FORCE_SECONDARY is a command."""
        from trapninja.ha.messages import HAMessageType
        
        assert HAMessageType.FORCE_SECONDARY.is_command is True

    def test_is_command_heartbeat(self):
        """Test HEARTBEAT is not a command."""
        from trapninja.ha.messages import HAMessageType
        
        assert HAMessageType.HEARTBEAT.is_command is False

    def test_is_config_sync(self):
        """Test config sync message types."""
        from trapninja.ha.messages import HAMessageType
        
        assert HAMessageType.CONFIG_SYNC.is_config_sync is True
        assert HAMessageType.CONFIG_REQUEST.is_config_sync is True
        assert HAMessageType.CONFIG_PUSH.is_config_sync is True
        assert HAMessageType.CONFIG_ACK.is_config_sync is True
        assert HAMessageType.HEARTBEAT.is_config_sync is False


class TestHAMessageCreation:
    """Tests for HAMessage creation."""

    def test_create_message(self):
        """Test creating HAMessage."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-instance-123",
            timestamp=time.time(),
            sequence=1,
            state=HAState.PRIMARY,
            priority=100,
            uptime=3600.0
        )
        
        assert msg.msg_type == HAMessageType.HEARTBEAT
        assert msg.sender_id == "test-instance-123"
        assert msg.state == HAState.PRIMARY
        assert msg.priority == 100

    def test_create_message_with_optional_fields(self):
        """Test creating HAMessage with optional fields."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.STATUS_RESPONSE,
            sender_id="test-instance",
            timestamp=time.time(),
            sequence=1,
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0,
            last_trap_time=time.time() - 5,
            payload={'status': 'ok'},
            config_checksum="abc123"
        )
        
        assert msg.last_trap_time is not None
        assert msg.payload == {'status': 'ok'}
        assert msg.config_checksum == "abc123"


class TestHAMessageSerialization:
    """Tests for HAMessage serialization."""

    def test_to_dict(self):
        """Test to_dict serialization."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-id",
            timestamp=1000.0,
            sequence=42,
            state=HAState.PRIMARY,
            priority=150,
            uptime=500.0
        )
        
        result = msg.to_dict()
        
        assert result['msg_type'] == "heartbeat"
        assert result['sender_id'] == "test-id"
        assert result['sequence'] == 42
        assert result['state'] == "primary"
        assert result['priority'] == 150

    def test_to_json(self):
        """Test to_json serialization."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-id",
            timestamp=1000.0,
            sequence=1,
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0
        )
        
        result = msg.to_json()
        
        assert isinstance(result, str)
        data = json.loads(result)
        assert data['msg_type'] == "heartbeat"

    def test_to_bytes(self):
        """Test to_bytes serialization."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-id",
            timestamp=1000.0,
            sequence=1,
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0
        )
        
        result = msg.to_bytes()
        
        assert isinstance(result, bytes)

    def test_from_dict(self):
        """Test from_dict deserialization."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        data = {
            'msg_type': 'heartbeat',
            'sender_id': 'test-id',
            'timestamp': 1000.0,
            'sequence': 1,
            'state': 'primary',
            'priority': 100,
            'uptime': 100.0
        }
        
        msg = HAMessage.from_dict(data)
        
        assert msg.msg_type == HAMessageType.HEARTBEAT
        assert msg.state == HAState.PRIMARY

    def test_from_json(self):
        """Test from_json deserialization."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        
        json_str = json.dumps({
            'msg_type': 'claim_primary',
            'sender_id': 'test-id',
            'timestamp': 1000.0,
            'sequence': 1,
            'state': 'secondary',
            'priority': 100,
            'uptime': 100.0
        })
        
        msg = HAMessage.from_json(json_str)
        
        assert msg.msg_type == HAMessageType.CLAIM_PRIMARY

    def test_from_bytes(self):
        """Test from_bytes deserialization."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        
        data = json.dumps({
            'msg_type': 'heartbeat',
            'sender_id': 'test-id',
            'timestamp': 1000.0,
            'sequence': 1,
            'state': 'primary',
            'priority': 100,
            'uptime': 100.0
        }).encode('utf-8')
        
        msg = HAMessage.from_bytes(data)
        
        assert msg.msg_type == HAMessageType.HEARTBEAT

    def test_roundtrip_serialization(self):
        """Test roundtrip serialization."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        original = HAMessage(
            msg_type=HAMessageType.STATUS_RESPONSE,
            sender_id="test-instance-abc",
            timestamp=1234567890.123,
            sequence=42,
            state=HAState.SECONDARY,
            priority=75,
            uptime=999.9,
            last_trap_time=1234567885.0,
            payload={'key': 'value'}
        )
        
        restored = HAMessage.from_bytes(original.to_bytes())
        
        assert restored.msg_type == original.msg_type
        assert restored.sender_id == original.sender_id
        assert restored.sequence == original.sequence
        assert restored.state == original.state
        assert restored.priority == original.priority


class TestHAMessageChecksum:
    """Tests for HAMessage checksum functionality."""

    def test_calculate_checksum(self):
        """Test calculate_checksum returns string."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-id",
            timestamp=1000.0,
            sequence=1,
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0
        )
        
        checksum = msg.calculate_checksum()
        
        assert isinstance(checksum, str)
        assert len(checksum) == 32  # MD5 hex length

    def test_sign_sets_checksum(self):
        """Test sign() sets checksum."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-id",
            timestamp=1000.0,
            sequence=1,
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0
        )
        
        assert msg.checksum is None
        
        msg.sign()
        
        assert msg.checksum is not None

    def test_sign_returns_self(self):
        """Test sign() returns self for chaining."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-id",
            timestamp=1000.0,
            sequence=1,
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0
        )
        
        result = msg.sign()
        
        assert result is msg

    def test_verify_valid_checksum(self):
        """Test verify() returns True for valid checksum."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-id",
            timestamp=1000.0,
            sequence=1,
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0
        )
        
        msg.sign()
        
        assert msg.verify() is True

    def test_verify_invalid_checksum(self):
        """Test verify() returns False for invalid checksum."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-id",
            timestamp=1000.0,
            sequence=1,
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0,
            checksum="invalid_checksum"
        )
        
        assert msg.verify() is False

    def test_verify_no_checksum(self):
        """Test verify() returns False when no checksum."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-id",
            timestamp=1000.0,
            sequence=1,
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0
        )
        
        assert msg.verify() is False

    def test_checksum_changes_with_content(self):
        """Test checksum changes when content changes."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg1 = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-id",
            timestamp=1000.0,
            sequence=1,
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0
        )
        
        msg2 = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-id",
            timestamp=1000.0,
            sequence=2,  # Different sequence
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0
        )
        
        assert msg1.calculate_checksum() != msg2.calculate_checksum()


class TestHAMessageStr:
    """Tests for HAMessage string representation."""

    def test_str_representation(self):
        """Test string representation."""
        from trapninja.ha.messages import HAMessage, HAMessageType
        from trapninja.ha.state import HAState
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="test-instance-123",
            timestamp=1000.0,
            sequence=42,
            state=HAState.PRIMARY,
            priority=100,
            uptime=100.0
        )
        
        result = str(msg)
        
        assert "heartbeat" in result
        assert "test-ins" in result  # Truncated sender_id
        assert "primary" in result
        assert "42" in result


class TestMessageFactoryInit:
    """Tests for MessageFactory initialization."""

    def test_initialization(self):
        """Test MessageFactory initialization."""
        from trapninja.ha.messages import MessageFactory
        
        factory = MessageFactory("instance-123", priority=150)
        
        assert factory.instance_id == "instance-123"
        assert factory.priority == 150

    def test_sequence_starts_at_zero(self):
        """Test sequence starts at zero."""
        from trapninja.ha.messages import MessageFactory
        
        factory = MessageFactory("instance-123", priority=100)
        
        assert factory._sequence == 0


class TestMessageFactoryCreation:
    """Tests for MessageFactory message creation."""

    def test_create_increments_sequence(self):
        """Test create() increments sequence."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance-123", priority=100)
        
        msg1 = factory.create(HAMessageType.HEARTBEAT, HAState.PRIMARY)
        msg2 = factory.create(HAMessageType.HEARTBEAT, HAState.PRIMARY)
        
        assert msg2.sequence == msg1.sequence + 1

    def test_create_signs_message(self):
        """Test create() signs the message."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance-123", priority=100)
        
        msg = factory.create(HAMessageType.HEARTBEAT, HAState.PRIMARY)
        
        assert msg.checksum is not None
        assert msg.verify() is True

    def test_create_sets_sender_id(self):
        """Test create() sets sender_id."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("my-instance", priority=100)
        
        msg = factory.create(HAMessageType.HEARTBEAT, HAState.PRIMARY)
        
        assert msg.sender_id == "my-instance"

    def test_create_sets_priority(self):
        """Test create() sets priority."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=200)
        
        msg = factory.create(HAMessageType.HEARTBEAT, HAState.PRIMARY)
        
        assert msg.priority == 200

    def test_create_sets_uptime(self):
        """Test create() sets uptime."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=100)
        
        # Wait a tiny bit
        time.sleep(0.01)
        
        msg = factory.create(HAMessageType.HEARTBEAT, HAState.PRIMARY)
        
        assert msg.uptime > 0


class TestMessageFactoryHelpers:
    """Tests for MessageFactory helper methods."""

    def test_heartbeat(self):
        """Test heartbeat() creates heartbeat message."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=100)
        
        msg = factory.heartbeat(HAState.PRIMARY)
        
        assert msg.msg_type == HAMessageType.HEARTBEAT
        assert msg.state == HAState.PRIMARY

    def test_heartbeat_ack(self):
        """Test heartbeat_ack() creates ack message."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=100)
        
        msg = factory.heartbeat_ack(HAState.SECONDARY)
        
        assert msg.msg_type == HAMessageType.HEARTBEAT_ACK
        assert msg.state == HAState.SECONDARY

    def test_claim_primary(self):
        """Test claim_primary() creates claim message."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=100)
        
        msg = factory.claim_primary(HAState.SECONDARY)
        
        assert msg.msg_type == HAMessageType.CLAIM_PRIMARY

    def test_yield_primary(self):
        """Test yield_primary() creates yield message."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=100)
        
        msg = factory.yield_primary(HAState.PRIMARY)
        
        assert msg.msg_type == HAMessageType.YIELD_PRIMARY

    def test_force_secondary(self):
        """Test force_secondary() creates force message."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=100)
        
        msg = factory.force_secondary(HAState.PRIMARY)
        
        assert msg.msg_type == HAMessageType.FORCE_SECONDARY

    def test_status_request(self):
        """Test status_request() creates request message."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=100)
        
        msg = factory.status_request(HAState.INITIALIZING)
        
        assert msg.msg_type == HAMessageType.STATUS_REQUEST

    def test_status_response(self):
        """Test status_response() creates response message."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=100)
        status = {'uptime': 100, 'state': 'primary'}
        
        msg = factory.status_response(HAState.PRIMARY, status)
        
        assert msg.msg_type == HAMessageType.STATUS_RESPONSE
        assert msg.payload == status

    def test_shutdown(self):
        """Test shutdown() creates shutdown message."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=100)
        
        msg = factory.shutdown(HAState.PRIMARY)
        
        assert msg.msg_type == HAMessageType.SHUTDOWN

    def test_config_request(self):
        """Test config_request() creates config request message."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=100)
        
        msg = factory.config_request(HAState.SECONDARY)
        
        assert msg.msg_type == HAMessageType.CONFIG_REQUEST

    def test_set_config_checksum(self):
        """Test set_config_checksum() sets checksum for future messages."""
        from trapninja.ha.messages import MessageFactory, HAMessageType
        from trapninja.ha.state import HAState
        
        factory = MessageFactory("instance", priority=100)
        factory.set_config_checksum("abc123")
        
        msg = factory.heartbeat(HAState.PRIMARY)
        
        assert msg.config_checksum == "abc123"
