from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import User, AuditLog, Notification
from schemas import UserOut, UpdateUserStatus
from auth import get_current_user, require_admin, hash_password

router = APIRouter(prefix="/api/users", tags=["users"])

def log(db, event, actor, detail=None):
    db.add(AuditLog(event_type=event, actor_username=actor, detail=detail))
    db.commit()

@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _=Depends(require_admin)):
    return db.query(User).order_by(User.id).all()

@router.post("")
def create_user(data: dict, db: Session = Depends(get_db), admin=Depends(require_admin)):
    from schemas import RegisterRequest
    u = User(
        username=data["username"], email=data["email"],
        password=hash_password(data["password"]),
        role=data.get("role","user"), status="active"
    )
    db.add(u); db.commit(); db.refresh(u)
    log(db, "user_created", admin.username, data["username"])
    return {"success": True, "user_id": u.id}

@router.patch("/{user_id}/status")
def update_status(user_id: int, data: UpdateUserStatus,
                  db: Session = Depends(get_db), admin=Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Utilisateur introuvable")
    old = user.status
    user.status = data.status
    db.commit()
    # Notification
    if data.status == "active":
        db.add(Notification(user_id=user_id, title="Compte approuve",
            message="Votre compte N.A.P.T a ete approuve. Vous pouvez maintenant vous connecter.",
            type="success"))
        db.commit()
    log(db, "user_status_changed", admin.username, f"{user.username}: {old} -> {data.status}")
    return {"success": True}


@router.patch("/{user_id}/role")
def update_role(user_id: int, data: dict, db: Session = Depends(get_db), admin=Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Utilisateur introuvable")
    old = user.role
    user.role = data.get("role", user.role)
    db.commit()
    log(db, "user_role_changed", admin.username, f"{user.username}: {old} -> {user.role}")
    return {"success": True}

@router.delete("/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), admin=Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.role == "admin":
        raise HTTPException(403, "Impossible de supprimer cet utilisateur")
    db.delete(user); db.commit()
    log(db, "user_deleted", admin.username, str(user_id))
    return {"success": True}

@router.get("/me", response_model=UserOut)
def me(current_user=Depends(get_current_user)):
    return current_user
