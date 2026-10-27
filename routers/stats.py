from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session
from database import get_db
from models import Scan, User, AuditLog
from auth import require_admin

router = APIRouter(prefix="/api/stats", tags=["stats"])

@router.get("")
def get_stats(db: Session = Depends(get_db), _=Depends(require_admin)):
    total_scans   = db.query(func.count(Scan.id)).scalar()
    done_scans    = db.query(func.count(Scan.id)).filter(Scan.status=="done").scalar()
    active_users  = db.query(func.count(User.id)).filter(User.status=="active").scalar()
    pending_users = db.query(func.count(User.id)).filter(User.status=="pending_admin").scalar()

    severity_dist = {}
    for row in db.query(Scan.severity, func.count(Scan.id)).group_by(Scan.severity).all():
        severity_dist[row[0] or "unknown"] = row[1]

    privilege_dist = {}
    for row in db.query(Scan.privilege, func.count(Scan.id)).group_by(Scan.privilege).all():
        privilege_dist[row[0] or "unknown"] = row[1]

    remediation_dist = {}
    for row in db.query(Scan.remediation_status, func.count(Scan.id)).group_by(Scan.remediation_status).all():
        remediation_dist[row[0]] = row[1]

    return {
        "total_scans": total_scans,
        "done_scans": done_scans,
        "active_users": active_users,
        "pending_users": pending_users,
        "severity": severity_dist,
        "privilege": privilege_dist,
        "remediation": remediation_dist,
    }
