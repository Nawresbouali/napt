from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import init_db
from config import settings
from routers import auth, users, scans, audit, stats, rag, llm, reports, invitations
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Creer admin par defaut
    from database import SessionLocal
    from models import User
    from auth import hash_password
    db = SessionLocal()
    if not db.query(User).filter(User.username == "nawres").first():
        db.add(User(username="nawres", email="nawres@napt.local",
                    password=hash_password("pfe2026"), role="admin", status="active"))
        db.commit()
        print("Admin cree : nawres / pfe2026")
    db.close()
    yield

app = FastAPI(title=settings.app_name, version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url, "http://localhost:3000", "http://localhost:5000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(scans.router)
app.include_router(audit.router)
app.include_router(stats.router)
app.include_router(rag.router)
app.include_router(llm.router)
app.include_router(reports.router)
app.include_router(invitations.router)
@app.get("/")
def root():
    return {"app": "N.A.P.T API", "version": "2.0.0", "status": "running",
            "docs": "/docs", "redoc": "/redoc"}
