import secrets, smtplib
from email.mime.text import MIMEText
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from database import get_db
from models import User, AuditLog
from schemas import RegisterRequest, LoginRequest, TokenResponse
from auth import hash_password, verify_password, create_access_token
from config import settings

router = APIRouter(prefix="/api/auth", tags=["auth"])

def log(db, event, actor=None, detail=None, ip=None, success=True):
    db.add(AuditLog(event_type=event, actor_username=actor, detail=detail, ip_address=ip, success=success))
    db.commit()

def send_verification_email(email: str, username: str, token: str) -> bool:
    link = "http://localhost:8000/api/auth/verify?token=" + token
    body = "Bonjour " + username + ",\n\nVerifiez votre email N.A.P.T :\n" + link
    body += "\n\nApres verification, un admin approuvera votre compte.\n\n— N.A.P.T"
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "Verifiez votre email — N.A.P.T"
    msg["From"] = "N.A.P.T <" + settings.smtp_user + ">"
    msg["To"] = email
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as s:
            s.starttls()
            s.login(settings.smtp_user, settings.smtp_pass)
            s.sendmail(settings.smtp_user, email, msg.as_string())
        return True
    except Exception as e:
        print("[EMAIL ERROR]", e)
        return False

@router.post("/register")
def register(data: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    if len(data.username) < 3:
        raise HTTPException(400, "Username trop court (min 3)")
    if len(data.password) < 8:
        raise HTTPException(400, "Mot de passe trop court (min 8)")
    if db.query(User).filter((User.username == data.username) | (User.email == data.email)).first():
        raise HTTPException(409, "Username ou email deja utilise")
    token = secrets.token_urlsafe(32)
    user = User(
        username=data.username, email=data.email,
        password=hash_password(data.password),
        email_token=token, status="pending_email"
    )
    db.add(user); db.commit()
    log(db, "register", data.username, data.email, request.client.host)
    sent = send_verification_email(data.email, data.username, token)
    resp = {"success": True, "message": "Email de verification envoye !"}
    if not sent:
        resp["dev_link"] = "/api/auth/verify?token=" + token
        resp["message"] = "EMAIL NON CONFIGURE — utilise dev_link"
    return resp

@router.get("/verify")
def verify_email(token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email_token == token).first()
    if not user:
        raise HTTPException(400, "Lien invalide ou deja utilise")
    user.status = "pending_admin"
    user.email_token = None
    db.commit()
    log(db, "email_verified", user.username)
    return {"success": True, "message": "Email verifie. En attente d'approbation admin."}

@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    ip = request.client.host
    if not user or not verify_password(data.password, user.password):
        log(db, "login_failed", data.username, "Bad credentials", ip, False)
        raise HTTPException(401, "Nom utilisateur ou mot de passe incorrect")
    msgs = {
        "pending_email": "Email non verifie. Verifiez votre boite mail.",
        "pending_admin": "Compte en attente approbation admin.",
        "disabled":      "Compte desactive. Contactez un administrateur."
    }
    if user.status in msgs:
        raise HTTPException(403, msgs[user.status])
    token = create_access_token({"sub": user.username, "role": user.role})
    log(db, "login_success", user.username, ip, True)
    return TokenResponse(
        access_token=token,
        user={"id": user.id, "username": user.username,
              "email": user.email, "role": user.role,
              "status": user.status}
    )
