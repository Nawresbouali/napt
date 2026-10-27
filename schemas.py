from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

# ── Auth ──────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

# ── User ──────────────────────────────────────────────────────
class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    status: str
    created_at: Optional[datetime]
    class Config: from_attributes = True

class UpdateUserStatus(BaseModel):
    status: str  # active | disabled | pending_admin

# ── Scan ──────────────────────────────────────────────────────
class LaunchScanRequest(BaseModel):
    target: str
    target_type: str = "vm"

class ScanOut(BaseModel):
    id: str
    target: str
    target_type: str
    status: str
    cve_id: Optional[str]
    product: Optional[str]
    privilege: Optional[str]
    cvss_score: Optional[str]
    severity: Optional[str]
    client_summary: Optional[str]
    remediation_status: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    class Config: from_attributes = True

class UpdateRemediation(BaseModel):
    status: str
    note: Optional[str] = None

# ── Chat ──────────────────────────────────────────────────────
class ChatRequest(BaseModel):
    message: str

# ── Notifications ─────────────────────────────────────────────
class NotificationOut(BaseModel):
    id: int
    title: str
    message: str
    type: str
    read: bool
    scan_id: Optional[str]
    created_at: Optional[datetime]
    class Config: from_attributes = True
