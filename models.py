from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    id         = Column(Integer, primary_key=True, index=True)
    username   = Column(String(50), unique=True, nullable=False, index=True)
    email      = Column(String(120), unique=True, nullable=False)
    password   = Column(String(200), nullable=False)
    role       = Column(String(20), default="user")        # user | admin
    status     = Column(String(30), default="pending_email")  # pending_email | pending_admin | active | disabled
    email_token = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scans      = relationship("Scan", back_populates="owner")
    notifications = relationship("Notification", back_populates="user")

class Scan(Base):
    __tablename__ = "scans"
    id                 = Column(String(36), primary_key=True)  # UUID
    target             = Column(String(200), nullable=False)
    target_type        = Column(String(30), default="vm")  # vm | web | wifi
    status             = Column(String(20), default="pending")  # pending|running|done|failed|stopped
    cve_id             = Column(String(50), nullable=True)
    product            = Column(String(100), nullable=True)
    privilege          = Column(String(50), nullable=True)
    cvss_score         = Column(String(10), nullable=True)
    severity           = Column(String(20), nullable=True)  # critical|high|medium|low
    remediation_status = Column(String(20), default="open")  # open|in_progress|resolved
    client_summary     = Column(Text, nullable=True)
    raw_output         = Column(Text, nullable=True)
    exploit_used       = Column(String(200), nullable=True)
    started_by_id      = Column(Integer, ForeignKey("users.id"))
    started_at         = Column(DateTime(timezone=True), server_default=func.now())
    finished_at        = Column(DateTime(timezone=True), nullable=True)
    owner              = relationship("User", back_populates="scans")
    remediation_logs   = relationship("RemediationLog", back_populates="scan")
    chat_messages      = relationship("ChatMessage", back_populates="scan")

class AuditLog(Base):
    __tablename__ = "audit_log"
    id              = Column(Integer, primary_key=True)
    event_type      = Column(String(50))
    actor_username  = Column(String(50), nullable=True)
    actor_email     = Column(String(120), nullable=True)
    target_username = Column(String(50), nullable=True)
    ip_address      = Column(String(45), nullable=True)
    detail          = Column(Text, nullable=True)
    success         = Column(Boolean, default=True)
    created_at      = Column(DateTime(timezone=True), server_default=func.now())

class Notification(Base):
    __tablename__ = "notifications"
    id         = Column(Integer, primary_key=True)
    user_id    = Column(Integer, ForeignKey("users.id"))
    title      = Column(String(200))
    message    = Column(Text)
    type       = Column(String(30), default="info")  # info|success|warning|error
    read       = Column(Boolean, default=False)
    scan_id    = Column(String(36), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user       = relationship("User", back_populates="notifications")

class RemediationLog(Base):
    __tablename__ = "remediation_log"
    id         = Column(Integer, primary_key=True)
    scan_id    = Column(String(36), ForeignKey("scans.id"))
    old_status = Column(String(20))
    new_status = Column(String(20))
    changed_by = Column(String(50))
    note       = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scan       = relationship("Scan", back_populates="remediation_logs")

class ChatMessage(Base):
    __tablename__ = "chat_message"
    id         = Column(Integer, primary_key=True)
    scan_id    = Column(String(36), ForeignKey("scans.id"))
    role       = Column(String(10))   # user | assistant
    content    = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scan       = relationship("Scan", back_populates="chat_messages")
class Invitation(Base):
    __tablename__ = "invitations"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    role = Column(String, default="user")
    token = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    used = Column(Boolean, default=False)
