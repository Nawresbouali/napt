import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

GMAIL_USER = "Nawresbouali10@gmail.com"
GMAIL_APP_PASSWORD = "yfxkchqgmwmjsjyd"
FRONTEND_URL = "http://localhost:5173"

def send_invitation_email(to_email: str, token: str, role: str = "user"):
    link = f"{FRONTEND_URL}/invite/{token}"

    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px;">
      <div style="max-width: 500px; margin: auto; background: #1e293b; border-radius: 12px; padding: 32px;">
        <h2 style="color: #38bdf8; margin-top: 0;">🔐 Invitation N.A.P.T</h2>
        <p>Vous avez été invité(e) à rejoindre la plateforme <strong>N.A.P.T</strong> en tant que <strong>{role}</strong>.</p>
        <p>Cliquez sur le bouton ci-dessous pour créer votre compte :</p>
        <a href="{link}" style="display:inline-block; background:#38bdf8; color:#0f172a; padding:12px 24px; border-radius:8px; text-decoration:none; font-weight:bold; margin: 16px 0;">
          Créer mon compte →
        </a>
        <p style="color:#94a3b8; font-size:12px; margin-top:24px;">
          Ce lien expire dans <strong>24 heures</strong>.<br>
          Si vous n'attendiez pas cette invitation, ignorez cet email.
        </p>
        <hr style="border-color:#334155; margin-top:24px;">
        <p style="color:#475569; font-size:11px;">N.A.P.T — Nawres Autonomous Pentest Tool</p>
      </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Invitation à rejoindre N.A.P.T"
    msg["From"] = GMAIL_USER
    msg["To"] = to_email
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, to_email, msg.as_string())
