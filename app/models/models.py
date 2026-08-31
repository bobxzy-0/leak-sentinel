import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Enum, ForeignKey, DateTime, Text, JSON
from sqlalchemy.orm import relationship
from app.models.base import Base

class RoleEnum(str, enum.Enum):
    admin = "admin"
    member = "member"

class AssetTypeEnum(str, enum.Enum):
    domain = "domain"
    email = "email"
    username = "username"
    password = "password"
    api_key = "api_key"

class AssetStatusEnum(str, enum.Enum):
    active = "active"
    paused = "paused"

class FindingSourceEnum(str, enum.Enum):
    hibp_breach = "hibp_breach"
    hibp_paste = "hibp_paste"
    hibp_stealer_log = "hibp_stealer_log"
    pwned_password = "pwned_password"
    hudson_rock = "hudson_rock"
    mozilla_monitor = "mozilla_monitor"

class ChannelTypeEnum(str, enum.Enum):
    dingtalk = "dingtalk"
    wecom = "wecom"
    email = "email"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    display_name = Column(String)
    role = Column(Enum(RoleEnum), default=RoleEnum.member, nullable=False)
    totp_secret = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class MonitoredAsset(Base):
    __tablename__ = "monitored_assets"
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    asset_type = Column(Enum(AssetTypeEnum), nullable=False)
    label = Column(String)
    value_ciphertext = Column(String, nullable=True) # Will be encrypted later
    value_hash = Column(String, index=True, nullable=True)
    status = Column(Enum(AssetStatusEnum), default=AssetStatusEnum.active)
    is_domain_verified = Column(Boolean, default=False)
    last_checked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    owner = relationship("User")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("monitored_assets.id"), nullable=True)
    source = Column(Enum(FindingSourceEnum), nullable=False)
    external_ref = Column(String, index=True)
    raw_data_json = Column(JSON, nullable=True)
    severity = Column(Integer, default=0)
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    is_new = Column(Boolean, default=True)
    fingerprint = Column(String, unique=True, index=True, nullable=False)
    
    asset = relationship("MonitoredAsset")

class AlertChannel(Base):
    __tablename__ = "alert_channels"
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    channel_type = Column(Enum(ChannelTypeEnum), nullable=False)
    config_ciphertext = Column(String, nullable=True) # Will be encrypted later
    is_enabled = Column(Boolean, default=True)
    name = Column(String, nullable=False, default="Default")
    
    owner = relationship("User")

class AlertLog(Base):
    __tablename__ = "alert_logs"
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    channel_id = Column(Integer, ForeignKey("alert_channels.id"), nullable=False)
    status = Column(String, nullable=False) # success / failed
    sent_at = Column(DateTime, default=datetime.utcnow)
    error_message = Column(Text, nullable=True)
    
    finding = relationship("Finding")
    channel = relationship("AlertChannel")

class HibpConfig(Base):
    __tablename__ = "hibp_config"
    id = Column(Integer, primary_key=True, index=True)
    api_key_ciphertext = Column(String, nullable=True)
    rate_limit_rpm = Column(Integer, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

class BreachCatalog(Base):
    __tablename__ = "breach_catalog"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    domain = Column(String, nullable=True)
    breach_date = Column(String, nullable=True)
    added_date = Column(String, nullable=True)
    pwn_count = Column(Integer, nullable=True)
    data_classes_json = Column(JSON, nullable=True)
    description = Column(Text, nullable=True)
    is_verified = Column(Boolean, default=True)
    is_sensitive = Column(Boolean, default=False)
    synced_at = Column(DateTime, default=datetime.utcnow)
