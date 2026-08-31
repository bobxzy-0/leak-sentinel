from pydantic import BaseModel, EmailStr
from typing import Literal, Optional
from datetime import datetime
from app.models.models import RoleEnum, AssetTypeEnum, AssetStatusEnum

# User Schemas
class UserBase(BaseModel):
    email: EmailStr
    display_name: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    role: RoleEnum
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}

# Token Schema
class Token(BaseModel):
    access_token: str
    token_type: str

# Asset Schemas
class AssetCreate(BaseModel):
    asset_type: AssetTypeEnum
    label: Optional[str] = None
    value: str
    site_filter_mode: Literal["all", "only"] = "all"
    watched_sites: list[str] = []

class AssetResponse(BaseModel):
    id: int
    asset_type: AssetTypeEnum
    label: Optional[str]
    value: str  # Decrypted value
    status: AssetStatusEnum
    is_domain_verified: bool
    last_checked_at: Optional[datetime]
    sort_order: int
    site_filter_mode: str
    watched_sites: list[str]
    created_at: datetime
    
    model_config = {"from_attributes": True}
