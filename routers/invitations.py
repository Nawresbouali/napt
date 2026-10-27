import secrets
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from database import Base, get_db
from routers.users import require_admin
from email_utils import send_invitation_email

router = APIRouter(prefix="/api/invitations", tags=["invitations"])

# ── Model (ajouter dans models.py) ──────────────────────────────────────────
# class Invitation(Base):
#     __tablename__ = "invitations"
#     id = Column(Integer, primary_key=True, index=True)
#     email = Column(String, unique=True, index=True)
#     role = Column(String, default="user")
#     token = Column(String, unique=True, index=True)
#     created_at = Column(DateTime, default=datetime.utcnow)
#     expires_at = Column(DateTime)
#     used = Column(Boolean, default=False)


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post("")
def create_invitation(data: dict, db: Session = Depends(get_db), admin=Depends(require_admin)):
    """Admin crée une invitation → envoie email"""
    from models import Invitation

    email = data.get("email")
    role = data.get("role", "user")

    if not email:
        raise HTTPException(400, "Email requis")

    # Supprimer ancienne invitation si existe
    old = db.query(Invitation).filter(Invitation.email == email).first()
    if old:
        db.delete(old)
        db.commit()

    token = secrets.token_urlsafe(32)
    inv = Invitation(
        email=email,
        role=role,
        token=token,
        expires_at=datetime.utcnow() + timedelta(hours=24),
        used=False
    )
    db.add(inv)
    db.commit()

    try:
        send_invitation_email(email, token, role)
        return {"success": True, "message": f"Invitation envoyée à {email}"}
    except Exception as e:
        # Supprimer l'invitation si l'email échoue
        db.delete(inv)
        db.commit()
        raise HTTPException(500, f"Erreur envoi email: {str(e)}")


@router.get("/{token}")
def validate_token(token: str, db: Session = Depends(get_db)):
    """Vérifie que le token est valide"""
    from models import Invitation

    inv = db.query(Invitation).filter(Invitation.token == token).first()
    if not inv:
        raise HTTPException(404, "Invitation invalide")
    if inv.used:
        raise HTTPException(400, "Invitation déjà utilisée")
    if datetime.utcnow() > inv.expires_at:
        raise HTTPException(400, "Invitation expirée")

    return {"email": inv.email, "role": inv.role}


@router.post("/{token}/accept")
def accept_invitation(token: str, data: dict, db: Session = Depends(get_db)):
    """L'utilisateur crée son compte via le token"""
    from models import Invitation, User
    from auth import hash_password

    inv = db.query(Invitation).filter(Invitation.token == token).first()
    if not inv:
        raise HTTPException(404, "Invitation invalide")
    if inv.used:
        raise HTTPException(400, "Invitation déjà utilisée")
    if datetime.utcnow() > inv.expires_at:
        raise HTTPException(400, "Invitation expirée")

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        raise HTTPException(400, "Username et mot de passe requis")
    if len(password) < 6:
        raise HTTPException(400, "Mot de passe trop court (min 6 caractères)")

    # Vérifier que username est unique
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "Ce nom d'utilisateur est déjà pris")

    
    user = User(
        username=username,
        email=inv.email,
        password=hash_password(password),
        role=inv.role,
        status="active"
    )
    db.add(user)

    inv.used = True
    db.commit()

    return {"success": True, "message": "Compte créé avec succès"}
