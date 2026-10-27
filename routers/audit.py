from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session
from database import get_db
from models import AuditLog, Notification
from auth import get_current_user, require_admin

router = APIRouter(prefix="/api", tags=["audit"])

@router.get("/audit")
def get_audit(limit: int = 100, db: Session = Depends(get_db), _=Depends(require_admin)):
    rows = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
    stats = {
        "total":   db.query(func.count(AuditLog.id)).scalar(),
        "logins":  db.query(func.count(AuditLog.id)).filter(AuditLog.event_type=="login_success").scalar(),
        "fails":   db.query(func.count(AuditLog.id)).filter(AuditLog.event_type=="login_failed").scalar(),
        "scans":   db.query(func.count(AuditLog.id)).filter(AuditLog.event_type=="scan_launched").scalar(),
        "regs":    db.query(func.count(AuditLog.id)).filter(AuditLog.event_type=="register").scalar(),
    }
    return {"log": [dict(r.__dict__) for r in rows], "stats": stats}

@router.get("/notifications")
def get_notifications(db: Session = Depends(get_db), user=Depends(get_current_user)):
    notifs = db.query(Notification).filter(
        Notification.user_id == user.id
    ).order_by(Notification.created_at.desc()).limit(50).all()
    return {"notifications": notifs, "unread": sum(1 for n in notifs if not n.read)}

@router.post("/notifications/{notif_id}/read")
def mark_read(notif_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    n = db.query(Notification).filter(Notification.id==notif_id, Notification.user_id==user.id).first()
    if n:
        n.read = True; db.commit()
    return {"success": True}
