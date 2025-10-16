#!/usr/bin/env python3
"""
ElectronX FIX Session Configuration Models

Pydantic models for FIX session configuration with validation
and JSON export functionality.
"""

from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
import json
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

logger = get_logger(__name__)


class SessionType(str, Enum):
    """FIX session type"""
    ORDER_ENTRY = "ORDER_ENTRY"
    MARKET_DATA = "MARKET_DATA"
    DROP_COPY = "DROP_COPY"


class TLSVersion(str, Enum):
    """Minimum TLS version"""
    TLS_1_2 = "1.2"
    TLS_1_3 = "1.3"


class SubscriptionType(str, Enum):
    """Market data subscription type"""
    SNAPSHOT = "SNAPSHOT"
    SNAPSHOT_PLUS_UPDATES = "SNAPSHOT_PLUS_UPDATES"


class MDEntryType(str, Enum):
    """Market data entry types"""
    BID = "BID"
    OFFER = "OFFER"
    TRADE = "TRADE"
    OPENING_PRICE = "OPENING_PRICE"
    CLOSING_PRICE = "CLOSING_PRICE"
    SETTLEMENT_PRICE = "SETTLEMENT_PRICE"
    TRADING_SESSION_HIGH = "TRADING_SESSION_HIGH"
    TRADING_SESSION_LOW = "TRADING_SESSION_LOW"
    TRADE_VOLUME = "TRADE_VOLUME"
    OPEN_INTEREST = "OPEN_INTEREST"
    TRADING_REFERENCE_PRICE = "TRADING_REFERENCE_PRICE"


class LogLevel(str, Enum):
    """Logging levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class ConnectionConfig(BaseModel):
    """Network connection configuration"""
    host: str = Field(..., description="Primary gateway hostname or IP")
    port: int = Field(..., ge=1, le=65535, description="Gateway port number")
    use_secondary: bool = Field(default=False, description="Use secondary/DR gateway")
    secondary_host: Optional[str] = Field(default=None, description="Secondary gateway hostname")
    secondary_port: Optional[int] = Field(default=None, ge=1, le=65535, description="Secondary gateway port")
    connect_timeout_ms: int = Field(default=30000, ge=1000, description="Connection timeout in milliseconds")
    socket_timeout_ms: int = Field(default=5000, ge=100, description="Socket I/O timeout in milliseconds")

    @field_validator('secondary_port')
    @classmethod
    def validate_secondary(cls, v, info):
        """Validate secondary port when secondary is enabled"""
        if info.data.get('use_secondary') and v is None:
            raise ValueError('secondary_port required when use_secondary is true')
        return v


class TLSConfig(BaseModel):
    """TLS/SSL configuration for mutual authentication"""
    client_cert_path: str = Field(..., description="Path to client certificate (.crt)")
    client_key_path: str = Field(..., description="Path to client private key (.key)")
    ca_cert_path: str = Field(..., description="Path to CA certificate (.crt)")
    verify_server: bool = Field(default=True, description="Verify server certificate")
    min_tls_version: TLSVersion = Field(default=TLSVersion.TLS_1_2, description="Minimum TLS version")


class FIXSessionConfig(BaseModel):
    """FIX protocol session configuration"""
    sender_comp_id: str = Field(..., description="SenderCompID - your assigned session identifier")
    target_comp_id: str = Field(default="EXI", description="TargetCompID - always EXI for ElectronX")
    sender_sub_id: Optional[str] = Field(default=None, description="SenderSubID - user email for order entry (Tag 50)")
    password: Optional[str] = Field(default=None, description="Session password if required (Tag 554)")
    heartbeat_interval: int = Field(default=30, ge=10, le=120, description="Heartbeat interval in seconds")
    reset_seq_num_on_logon: bool = Field(default=True, description="Reset sequence numbers on logon (Tag 141)")
    enable_weekly_reset: bool = Field(default=True, description="Enable weekly Sunday 06:15 UTC sequence reset")
    weekly_reset_day: str = Field(default="Sunday", description="Day of week for sequence reset")
    weekly_reset_time_utc: str = Field(default="06:15:00", description="Time in UTC for weekly reset")

    @field_validator('target_comp_id')
    @classmethod
    def validate_target(cls, v):
        """Ensure TargetCompID is EXI"""
        if v != "EXI":
            raise ValueError('target_comp_id must be "EXI" for ElectronX')
        return v


class TradingConfig(BaseModel):
    """Trading-specific configuration for order entry sessions"""
    default_account: str = Field(..., description="Default trading account (Tag 1)")
    customer_order_capacity: int = Field(..., ge=1, le=4, description="CTI code (Tag 582): 1=OWN, 2=PROP, 3=ADVISOR, 4=OTHER")
    manual_order_indicator: bool = Field(default=False, description="Manual order indicator (Tag 1028)")


class MarketDataConfig(BaseModel):
    """Market data subscription configuration"""
    auto_subscribe_symbols: List[str] = Field(default_factory=list, description="Symbols to auto-subscribe on logon")
    subscription_type: SubscriptionType = Field(default=SubscriptionType.SNAPSHOT_PLUS_UPDATES)
    market_depth: int = Field(default=0, ge=0, le=25, description="Market depth: 0=full, 1=top, 2+=levels")
    entry_types: List[MDEntryType] = Field(
        default=[MDEntryType.BID, MDEntryType.OFFER, MDEntryType.TRADE],
        description="Market data entry types to request"
    )


class ReconnectConfig(BaseModel):
    """Automatic reconnection configuration"""
    enabled: bool = Field(default=True, description="Enable automatic reconnection")
    max_attempts: int = Field(default=-1, description="Max reconnect attempts (-1 = infinite)")
    interval_ms: int = Field(default=60000, ge=1000, description="Initial reconnect interval in milliseconds")
    backoff_multiplier: float = Field(default=1.5, ge=1.0, le=5.0, description="Exponential backoff multiplier")
    max_interval_ms: int = Field(default=300000, ge=1000, description="Maximum reconnect interval")


class RateLimitingConfig(BaseModel):
    """Message rate limiting configuration"""
    max_messages_per_second: int = Field(default=50, ge=1, description="Maximum messages per second")
    burst_allowance: int = Field(default=10, ge=0, description="Burst allowance above rate limit")


class SessionConfig(BaseModel):
    """Complete FIX session configuration"""
    session_id: str = Field(..., description="Unique session identifier")
    enabled: bool = Field(default=True, description="Enable this session")
    session_type: SessionType = Field(..., description="Type of FIX session")
    description: str = Field(default="", description="Human-readable description")

    connection: ConnectionConfig
    tls: TLSConfig
    fix_session: FIXSessionConfig

    trading: Optional[TradingConfig] = Field(default=None, description="Trading config (ORDER_ENTRY only)")
    market_data: Optional[MarketDataConfig] = Field(default=None, description="Market data config (MARKET_DATA only)")
    reconnect: ReconnectConfig = Field(default_factory=ReconnectConfig)
    rate_limiting: Optional[RateLimitingConfig] = Field(default=None, description="Rate limiting (ORDER_ENTRY only)")

    @field_validator('trading')
    @classmethod
    def validate_trading_config(cls, v, info):
        """Ensure trading config present for ORDER_ENTRY sessions"""
        if info.data.get('session_type') == SessionType.ORDER_ENTRY and v is None:
            raise ValueError('trading configuration required for ORDER_ENTRY sessions')
        return v

    @field_validator('market_data')
    @classmethod
    def validate_market_data_config(cls, v, info):
        """Ensure market data config present for MARKET_DATA sessions"""
        if info.data.get('session_type') == SessionType.MARKET_DATA and v is None:
            raise ValueError('market_data configuration required for MARKET_DATA sessions')
        return v


class GlobalConfig(BaseModel):
    """Global application configuration"""
    log_directory: str = Field(default="/var/log/electronx", description="Directory for log files")
    log_level: LogLevel = Field(default=LogLevel.INFO, description="Logging level")
    log_fix_messages: bool = Field(default=True, description="Log all FIX messages")
    store_directory: str = Field(default="/var/electronx/store", description="Directory for message store")
    enable_message_persistence: bool = Field(default=True, description="Persist messages to disk")


class MultiSessionConfig(BaseModel):
    """Configuration for multiple FIX sessions"""
    sessions: List[SessionConfig]
    global_config: GlobalConfig = Field(default_factory=GlobalConfig, alias="global")

    class Config:
        populate_by_name = True


def create_order_entry_config(
    customer_label: str = "POLARIS",
    trading_desk: str = "01",
    session_num: str = "01",
    host: str = "primary.electronx.com",
    user_email: str = "john.smith@polaristrading.com",
    trading_account: str = "TA-POLARIS-00001",
    cert_dir: str = "/path/to/certs"
) -> SessionConfig:
    """
    Create an Order Entry session configuration

    Args:
        customer_label: Customer label (e.g., POLARIS)
        trading_desk: Trading desk number (e.g., 01)
        session_num: Session number for this desk (e.g., 01)
        host: ElectronX gateway hostname
        user_email: Authorized trading user email
        trading_account: Trading account ID
        cert_dir: Directory containing TLS certificates
    """
    sender_comp_id = f"D-{customer_label}-{trading_desk}-OE{session_num}"

    logger.debug(f"Creating order entry config for {sender_comp_id}")

    return SessionConfig(
        session_id=f"order_entry_{trading_desk}_{session_num}",
        enabled=True,
        session_type=SessionType.ORDER_ENTRY,
        description=f"Order entry session for trading desk D-{customer_label}-{trading_desk}",
        connection=ConnectionConfig(
            host=host,
            port=13101,
            use_secondary=False,
            secondary_host=f"secondary.electronx.com",
            secondary_port=13101
        ),
        tls=TLSConfig(
            client_cert_path=f"{cert_dir}/client.crt",
            client_key_path=f"{cert_dir}/client.key",
            ca_cert_path=f"{cert_dir}/ca.crt"
        ),
        fix_session=FIXSessionConfig(
            sender_comp_id=sender_comp_id,
            sender_sub_id=user_email,
            heartbeat_interval=30,
            reset_seq_num_on_logon=True,
            enable_weekly_reset=True
        ),
        trading=TradingConfig(
            default_account=trading_account,
            customer_order_capacity=2,  # PROPRIETARY_ACCOUNT
            manual_order_indicator=False
        ),
        rate_limiting=RateLimitingConfig(
            max_messages_per_second=50,
            burst_allowance=10
        )
    )


def create_market_data_config(
    customer_label: str = "POLARIS",
    session_num: str = "01",
    host: str = "primary.electronx.com",
    symbols: List[str] = None,
    cert_dir: str = "/path/to/certs"
) -> SessionConfig:
    """
    Create a Market Data session configuration

    Args:
        customer_label: Customer label (e.g., POLARIS)
        session_num: Session number (e.g., 01)
        host: ElectronX gateway hostname
        symbols: List of symbols to auto-subscribe
        cert_dir: Directory containing TLS certificates
    """
    if symbols is None:
        symbols = ["GOOG", "AAPL", "MSFT"]

    sender_comp_id = f"{customer_label}-MD{session_num}"

    logger.debug(f"Creating market data config for {sender_comp_id}")

    return SessionConfig(
        session_id=f"market_data_{session_num}",
        enabled=True,
        session_type=SessionType.MARKET_DATA,
        description=f"Market data session {session_num} for {customer_label}",
        connection=ConnectionConfig(
            host=host,
            port=13001,  # Market Data Gateway port
            use_secondary=False,
            secondary_host=f"secondary.electronx.com",
            secondary_port=13001
        ),
        tls=TLSConfig(
            client_cert_path=f"{cert_dir}/client.crt",
            client_key_path=f"{cert_dir}/client.key",
            ca_cert_path=f"{cert_dir}/ca.crt"
        ),
        fix_session=FIXSessionConfig(
            sender_comp_id=sender_comp_id,
            sender_sub_id=None,  # Not required for market data
            heartbeat_interval=30,
            reset_seq_num_on_logon=True,
            enable_weekly_reset=True
        ),
        market_data=MarketDataConfig(
            auto_subscribe_symbols=symbols,
            subscription_type=SubscriptionType.SNAPSHOT_PLUS_UPDATES,
            market_depth=0,  # Full book
            entry_types=[MDEntryType.BID, MDEntryType.OFFER, MDEntryType.TRADE]
        )
    )


def create_drop_copy_config(
    customer_label: str = "POLARIS",
    clearing_member: str = "01",
    session_num: str = "01",
    host: str = "primary.electronx.com",
    cert_dir: str = "/path/to/certs"
) -> SessionConfig:
    """
    Create a Drop Copy session configuration

    Args:
        customer_label: Customer label (e.g., POLARIS)
        clearing_member: Clearing member number (e.g., 01)
        session_num: Session number (e.g., 01)
        host: ElectronX gateway hostname
        cert_dir: Directory containing TLS certificates
    """
    sender_comp_id = f"CM-{customer_label}-{clearing_member}-DC{session_num}"

    logger.debug(f"Creating drop copy config for {sender_comp_id}")

    return SessionConfig(
        session_id=f"drop_copy_{clearing_member}_{session_num}",
        enabled=True,
        session_type=SessionType.DROP_COPY,
        description=f"Drop copy session for clearing member CM-{customer_label}-{clearing_member}",
        connection=ConnectionConfig(
            host=host,
            port=13101,  # Order Entry Gateway (same as order entry)
            use_secondary=False,
            secondary_host=f"secondary.electronx.com",
            secondary_port=13101
        ),
        tls=TLSConfig(
            client_cert_path=f"{cert_dir}/client.crt",
            client_key_path=f"{cert_dir}/client.key",
            ca_cert_path=f"{cert_dir}/ca.crt"
        ),
        fix_session=FIXSessionConfig(
            sender_comp_id=sender_comp_id,
            sender_sub_id=None,  # Not required for drop copy
            heartbeat_interval=30,
            reset_seq_num_on_logon=True,
            enable_weekly_reset=True
        )
    )


def generate_config_files(
    output_dir: str = "./config",
    customer_label: str = "POLARIS",
    host: str = "primary.electronx.com",
    cert_dir: str = "/path/to/certs"
):
    """
    Generate sample configuration files for all three session types

    Args:
        output_dir: Directory to write config files
        customer_label: Customer label
        host: ElectronX gateway hostname
        cert_dir: Directory containing TLS certificates
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    logger.info("Generating ElectronX FIX session configuration files...")
    logger.info("=" * 60)

    # Create Order Entry config
    try:
        oe_config = create_order_entry_config(
            customer_label=customer_label,
            host=host,
            cert_dir=cert_dir,
            user_email="john.smith@polaristrading.com",
            trading_account=f"TA-{customer_label}-00001"
        )

        oe_file = output_path / "order_entry_session.json"
        with open(oe_file, "w") as f:
            json.dump(oe_config.model_dump(exclude_none=True, by_alias=True), f, indent=2)
        logger.info(f"✓ Created: {oe_file}")
    except Exception as e:
        logger.error(f"Failed to create order entry config: {e}")
        raise

    # Create Market Data config
    try:
        md_config = create_market_data_config(
            customer_label=customer_label,
            host=host,
            cert_dir=cert_dir,
            symbols=["GOOG", "AAPL", "MSFT", "TSLA"]
        )

        md_file = output_path / "market_data_session.json"
        with open(md_file, "w") as f:
            json.dump(md_config.model_dump(exclude_none=True, by_alias=True), f, indent=2)
        logger.info(f"✓ Created: {md_file}")
    except Exception as e:
        logger.error(f"Failed to create market data config: {e}")
        raise

    # Create Drop Copy config
    try:
        dc_config = create_drop_copy_config(
            customer_label=customer_label,
            host=host,
            cert_dir=cert_dir
        )

        dc_file = output_path / "drop_copy_session.json"
        with open(dc_file, "w") as f:
            json.dump(dc_config.model_dump(exclude_none=True, by_alias=True), f, indent=2)
        logger.info(f"✓ Created: {dc_file}")
    except Exception as e:
        logger.error(f"Failed to create drop copy config: {e}")
        raise

    # Create combined multi-session config
    try:
        multi_config = MultiSessionConfig(
            sessions=[oe_config, md_config, dc_config],
            global_config=GlobalConfig()
        )

        multi_file = output_path / "all_sessions.json"
        with open(multi_file, "w") as f:
            json.dump(multi_config.model_dump(exclude_none=True, by_alias=True), f, indent=2)
        logger.info(f"✓ Created: {multi_file}")
    except Exception as e:
        logger.error(f"Failed to create multi-session config: {e}")
        raise

    logger.info("=" * 60)
    logger.info("Configuration files generated successfully!")
    logger.info("")
    logger.info("Next steps:")
    logger.info("1. Update certificate paths in the JSON files")
    logger.info("2. Replace 'primary.electronx.com' with actual gateway IP")
    logger.info("3. Update SenderCompID values with your assigned identifiers")
    logger.info("4. Set authorized user emails and trading accounts")


if __name__ == "__main__":
    """Generate example configuration files"""
    from utils.logger import setup_logger

    # Setup logger for this script
    setup_logger(name=__name__, level="INFO")

    generate_config_files(
        output_dir="./config",
        customer_label="POLARIS",
        host="primary.electronx.com",
        cert_dir="/path/to/certs"
    )
