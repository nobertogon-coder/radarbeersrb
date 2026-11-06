# -*- coding: utf-8 -*-
import os
import io
import re
import hashlib
import datetime
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import pdfplumber
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float, ForeignKey, desc, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

import clinical_rules

# ==============================================================================
# BASE DE DADOS POSTGRESQL / SQLITE
# ==============================================================================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./farmbeers.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    pool_recycle=300
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def hash_password(password: str) -> str:
    salt = "FB_CLINICAL_SALT_2026"
    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password = Column(String(100), nullable=False)
    role = Column(String(20), default="pharmacist")
    is_active = Column(Boolean, default=True)
    last_ping = Column(DateTime, default=datetime.datetime.utcnow)

class ScreeningRecord(Base):
    __tablename__ = "screenings"
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    pharmacist_username = Column(String(50), default="admin", nullable=True)
    sector = Column(String(50), default="Enfermaria", nullable=False)
    patient_age = Column(Integer, default=70, nullable=True)
    crcl_ml_min = Column(Float, nullable=True)
    acb_score = Column(Integer, default=0, nullable=True)
    total_alerts = Column(Integer, default=0, nullable=True)
    alerts = relationship("ScreeningAlertRecord", back_populates="screening", cascade="all, delete-orphan")

class ScreeningAlertRecord(Base):
    __tablename__ = "screening_alerts"
    id = Column(Integer, primary_key=True, index=True)
    screening_id = Column(Integer, ForeignKey("screenings.id", ondelete="CASCADE"), nullable=True)
    drug_name = Column(String(150), nullable=False, default="Medicamento")
    axis = Column(String(100), nullable=False, default="AGS Beers 2023")
    recommendation = Column(String(1000), nullable=False, default="Reavaliar prescrição.")
    outcome = Column(String(30), default="pending", nullable=True)
    screening = relationship("ScreeningRecord", back_populates="alerts")

Base.metadata.create_all(bind=engine)

def run_auto_migrations():
    with engine.connect() as conn:
        try:
            if not DATABASE_URL.startswith("sqlite"):
                conn.execute(text("ALTER TABLE screening_alerts ADD COLUMN IF NOT EXISTS outcome VARCHAR(30) DEFAULT 'pending';"))
                conn.execute(text("ALTER TABLE screenings ADD COLUMN IF NOT EXISTS total_alerts INTEGER DEFAULT 0;"))
                conn.execute(text("ALTER TABLE screenings ADD COLUMN IF NOT EXISTS acb_score INTEGER DEFAULT 0;"))
                conn.execute(text("ALTER TABLE screenings ADD COLUMN IF NOT EXISTS crcl_ml_min DOUBLE PRECISION;"))
                conn.commit()
        except Exception:
            pass
run_auto_migrations()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_default_users():
    db = SessionLocal()
    try:
        defaults = [
            ("admin", "admin123", "admin"),
            ("farmaceutico", "farm123", "pharmacist"),
            ("Teste", "teste123", "pharmacist")
        ]
        for u, p, r in defaults:
            user = db.query(User).filter(User.username == u).first()
            if not user:
                new_user = User(
                    username=u, password=hash_password(p), role=r,
                    is_active=True, last_ping=datetime.datetime.utcnow()
                )
                db.add(new_user)
            else:
                if user.password == p:
                    user.password = hash_password(p)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

init_default_users()

app = FastAPI(title="Radar Beers API", version="10.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoginRequest(BaseModel):
    username: str
    password: str

class PingRequest(BaseModel):
    username: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str

class OutcomeRequest(BaseModel):
    outcome: str

class TextExtractRequest(BaseModel):
    text: str

class MedicationInput(BaseModel):
    name: str
    dose: Optional[str] = ""
    route: Optional[str] = "VO (Oral)"
    frequency: Optional[str] = ""
    is_sos: Optional[bool] = False

class ScreeningPayload(BaseModel):
    age: Optional[int] = 70
    sector: Optional[str] = "Enfermaria"
    fall_risk: Optional[bool] = False
    conditions: Optional[List[str]] = []
    crcl_ml_min: Optional[float] = None
    crcl_notes: Optional[str] = ""
    medications: List[MedicationInput] = []
    persist: Optional[bool] = True

# ==============================================================================
# AUTENTICAÇÃO E USUÁRIOS
# ==============================================================================
@app.post("/api/v1/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    pwd_h = hash_password(payload.password)
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or (user.password != pwd_h and user.password != payload.password):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos.")
    if user.password == payload.password:
        user.password = pwd_h
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Acesso bloqueado pela administração.")
    user.last_ping = datetime.datetime.utcnow()
    db.commit()
    return {"status": "ok", "user": {"id": user.id, "username": user.username, "role": user.role}}

@app.post("/api/v1/auth/ping")
def ping_user(payload: PingRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if user:
        user.last_ping = datetime.datetime.utcnow()
        db.commit()
    return {"status": "alive"}

@app.post("/api/v1/auth/logout")
def logout_user(payload: PingRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if user:
        user.last_ping = datetime.datetime.utcnow() - datetime.timedelta(minutes=10)
        db.commit()
    return {"status": "logged_out"}

@app.get("/api/v1/admin/users")
def list_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    now = datetime.datetime.utcnow()
    return [{
        "id": u.id, "username": u.username, "role": u.role,
        "is_active": u.is_active,
        "is_online": bool(u.last_ping and (now - u.last_ping).total_seconds() <= 60)
    } for u in users]

@app.post("/api/v1/admin/users")
def create_user(payload: CreateUserRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Nome de usuário já cadastrado.")
    new_u = User(
        username=payload.username, password=hash_password(payload.password),
        role=payload.role, is_active=True, last_ping=datetime.datetime.utcnow()
    )
    db.add(new_u)
    db.commit()
    return {"status": "created"}

@app.patch("/api/v1/admin/users/{user_id}/toggle-status")
def toggle_user_status(user_id: int, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    if u.username == "admin":
        raise HTTPException(status_code=400, detail="Não é permitido bloquear o administrador padrão.")
    u.is_active = not u.is_active
    db.commit()
    return {"status": "updated", "is_active": u.is_active}

@app.delete("/api/v1/admin/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    if u.username == "admin":
        raise HTTPException(status_code=400, detail="Não é permitido excluir o administrador padrão.")
    db.delete(u)
    db.commit()
    return {"status": "deleted"}

# ==============================================================================
# MÉTRICAS (EXCLUSIVO ENFERMARIA)
# ==============================================================================
@app.get("/api/v1/admin/metrics")
def get_metrics(year: Optional[str] = None, month: Optional[str] = None, day: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        all_screenings = db.query(ScreeningRecord).order_by(desc(ScreeningRecord.created_at)).all()
        screenings = []
        for s in all_screenings:
            dt = s.created_at
            if dt and year and year.strip().isdigit() and dt.year != int(year.strip()):
                continue
            if dt and month and month.strip().isdigit() and dt.month != int(month.strip()):
                continue
            if dt and day and day.strip().isdigit() and dt.day != int(day.strip()):
                continue
            screenings.append(s)

        total_patients = len(screenings)
        s_ids = [s.id for s in screenings]

        if s_ids:
            alerts = db.query(ScreeningAlertRecord).filter(ScreeningAlertRecord.screening_id.in_(s_ids)).all()
            total_alerts = len(alerts)
            accepted_count = sum(1 for a in alerts if a.outcome == "accepted")
            counts = {}
            for a in alerts:
                d_name = a.drug_name or "Medicamento"
                counts[d_name] = counts.get(d_name, 0) + 1
            sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
            top_5 = [{"drug": k, "count": v} for k, v in sorted_counts]
        else:
            total_alerts = sum((s.total_alerts or 0) for s in screenings)
            accepted_count = 0
            top_5 = []

        acceptance_rate = round((accepted_count / total_alerts * 100), 1) if total_alerts > 0 else 0.0

        return {
            "total_patients": total_patients,
            "count_enfermaria": total_patients,
            "total_beers_alerts": total_alerts,
            "accepted_interventions": accepted_count,
            "acceptance_rate": acceptance_rate,
            "top_5_beers": top_5
        }
    except Exception:
        return {
            "total_patients": 0, "count_enfermaria": 0,
            "total_beers_alerts": 0, "accepted_interventions": 0,
            "acceptance_rate": 0.0, "top_5_beers": []
        }

@app.patch("/api/v1/alerts/{alert_id}/outcome")
def update_alert_outcome(alert_id: int, payload: OutcomeRequest, db: Session = Depends(get_db)):
    try:
        alert_rec = db.query(ScreeningAlertRecord).filter(ScreeningAlertRecord.id == alert_id).first()
        if not alert_rec:
            return {"status": "not_found", "alert_id": alert_id}
        alert_rec.outcome = payload.outcome
        db.commit()
        return {"status": "updated", "alert_id": alert_id, "outcome": alert_rec.outcome}
    except Exception as e:
        db.rollback()
        return {"status": "error", "detail": str(e)}

# ==============================================================================
# MOTOR DE TRIAGEM
# ==============================================================================
@app.post("/api/v1/screen")
def process_screening(payload: ScreeningPayload, db: Session = Depends(get_db)):
    patient_age = payload.age if (payload.age and payload.age > 0) else 70
    med_dicts = [m.model_dump() for m in payload.medications]

    alerts_raw, acb_total, acb_text, med_tag_map = clinical_rules.evaluate_patient_beers(
        medications=med_dicts,
        age=patient_age,
        fall_risk=bool(payload.fall_risk),
        conditions=payload.conditions or [],
        crcl=payload.crcl_ml_min
    )

    persisted_records = []
    if payload.medications and payload.persist:
        try:
            record = ScreeningRecord(
                pharmacist_username="admin",
                sector="Enfermaria",
                patient_age=int(patient_age),
                crcl_ml_min=float(payload.crcl_ml_min) if payload.crcl_ml_min is not None else None,
                acb_score=int(acb_total),
                total_alerts=len(alerts_raw),
                created_at=datetime.datetime.utcnow()
            )
            db.add(record)
            db.commit()
            db.refresh(record)

            for a in alerts_raw:
                d_name = str(a.get("drug", "Medicamento"))
                alert_rec = ScreeningAlertRecord(
                    screening_id=record.id,
                    drug_name=d_name,
                    axis=str(a.get("axis", "AGS Beers 2023")),
                    recommendation=str(a.get("recommendation", "Reavaliar prescrição.")),
                    outcome="pending"
                )
                db.add(alert_rec)
                db.commit()
                db.refresh(alert_rec)
                persisted_records.append(alert_rec.id)
        except Exception:
            db.rollback()

    alerts_complete = []
    for idx, a in enumerate(alerts_raw):
        alerts_complete.append({
            "id": persisted_records[idx] if idx < len(persisted_records) else None,
            "drug": a.get("drug"),
            "drug_name": a.get("drug"),
            "axis": a.get("axis"),
            "recommendation": a.get("recommendation"),
            "rationale": a.get("rationale"),
            "tapering": a.get("tapering"),
            "is_sos": a.get("is_sos", False),
            "acb_score": a.get("acb_score", 0),
            "outcome": "pending"
        })

    alert_by_canonical = {a["drug"].strip().lower(): a for a in alerts_complete}

    med_rows = []
    for m in payload.medications:
        canonical_name = clinical_rules.identify_drug_canonical(m.name)
        matched = alert_by_canonical.get(canonical_name.lower()) if canonical_name else None

        parts = [p for p in [m.dose, m.route, m.frequency] if p and p.strip()]
        dose_route_str = " ".join(parts) if parts else "VO (Oral)"

        is_sn_flag = bool(m.is_sos) or any(t in dose_route_str.lower() for t in ["sn", "qn", "sos", "necessario", "necessário"])
        if is_sn_flag and "[SN/QN]" not in dose_route_str:
            dose_route_str = f"{dose_route_str} [SN/QN]"

        tag_str = ""
        is_beers = False

        if canonical_name and canonical_name in med_tag_map:
            tag_str = med_tag_map[canonical_name]
            is_beers = True
        elif matched:
            tag_str = matched.get("axis", "AGS Beers 2023")
            is_beers = True

        med_rows.append({
            "name": canonical_name.capitalize() if canonical_name else m.name,
            "dose_route": dose_route_str,
            "is_beers": is_beers,
            "is_sos": is_sn_flag,
            "alert_tag": tag_str
        })

    return {
        "total_beers_alerts": len(alerts_complete),
        "acb_score": acb_total,
        "acb_interpretation": acb_text,
        "alerts": alerts_complete,
        "medication_rows": med_rows
    }

# ==============================================================================
# EXTRAÇÃO DE TEXTO E PDF HOSPITALAR
# ==============================================================================
def extract_posology_details(line: str):
    dose = ""
    route = "VO (Oral)"
    freq = ""
    is_sn = False

    m_dose = re.search(r'(\b\d+[\.,]?\d*\s*(?:mg|g|mcg|ml|gotas|gota|ampola|amp|cp|comp|frasco|ui)\b)', line, re.I)
    if m_dose:
        dose = m_dose.group(1).strip()

    if re.search(r'\b(iv|ev|endovenos[ao]|intravenos[ao])\b', line, re.I):
        route = "IV (Endovenoso)"
    elif re.search(r'\b(im|intramuscular)\b', line, re.I):
        route = "IM (Intramuscular)"
    elif re.search(r'\b(sc|subcutane[ao])\b', line, re.I):
        route = "SC (Subcutâneo)"
    elif re.search(r'\b(inalat[oó]ri[ao]|neb|inal)\b', line, re.I):
        route = "Inalatório"
    elif re.search(r'\b(t[oó]pic[ao]|creme|pomada)\b', line, re.I):
        route = "Tópico"

    if re.search(r'\b(sn|qn|sos|se\s+necess[aá]rio|quando\s+necess[aá]rio|a\s+crit[eé]rio\s+m[eé]dico|acm)\b', line, re.I):
        is_sn = True
        freq = "SN (Se Necessário)"
    else:
        m_freq = re.search(r'(\b\d{1,2}\s*/\s*\d{1,2}\s*h|\b\d{1,2}\s*em\s*\d{1,2}\s*h|\b\d{1,2}x\s*/\s*dia|\b\d{1,2}x\s*ao\s*dia|\b1x\b|\b2x\b|\b3x\b|\b4x\b|\bmanh[aã]\b|\bnoite\b|\b12/12h\b|\b8/8h\b|\b6/6h\b|\b24/24h\b)', line, re.I)
        if m_freq:
            freq = m_freq.group(1).strip()

    return dose, route, freq, is_sn

def parse_prescription_lines(raw_text: str):
    extracted_items = []
    seen_generics = set()
    for line in raw_text.split("\n"):
        line_clean = line.strip()
        if not line_clean:
            continue
        normalized_line = clinical_rules.normalize_text(line_clean)
        found_generics_in_line = []
        for generic, synonyms in clinical_rules.BEERS_DRUGS.items():
            for syn in synonyms:
                if clinical_rules.normalize_text(syn) in normalized_line:
                    if generic not in found_generics_in_line:
                        found_generics_in_line.append(generic)
                    break
        for generic in found_generics_in_line:
            if generic not in seen_generics:
                seen_generics.add(generic)
                dose, route, freq, is_sn = extract_posology_details(line_clean)
                extracted_items.append({
                    "name": generic.capitalize(),
                    "dose": dose,
                    "route": route,
                    "frequency": freq,
                    "is_sos": is_sn
                })
    return extracted_items

@app.post("/api/v1/prescription/extract-pdf")
async def extract_pdf(file: UploadFile = File(...)):
    contents = await file.read()
    full_text = ""
    try:
        with pdfplumber.open(io.BytesIO(contents)) as pdf:
            for page in pdf.pages:
                t = page.extract_text()
                if t:
                    full_text += t + "\n"
        extracted_items = parse_prescription_lines(full_text)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao ler PDF: {str(e)}")

    drug_names = [it["name"] for it in extracted_items]
    return {"medications": drug_names, "drugs": drug_names, "items": extracted_items}

@app.post("/api/v1/prescription/extract-text")
def extract_text(payload: TextExtractRequest):
    extracted_items = parse_prescription_lines(payload.text)
    drug_names = [it["name"] for it in extracted_items]
    return {"medications": drug_names, "drugs": drug_names, "items": extracted_items}

# ==============================================================================
# ROTAS DO FRONTEND, MANUAL E LOGO
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
def read_root():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Radar Beers Online. Arquivo index.html não localizado.</h1>"

@app.get("/manual.html", response_class=HTMLResponse)
def read_manual():
    if os.path.exists("manual.html"):
        with open("manual.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Manual Operacional não encontrado.</h1>"

# ROTA PARA ENTREGAR A SUA LOGO
@app.get("/logo.jpg")
def get_logo():
    if os.path.exists("logo.jpg"):
        return FileResponse("logo.jpg")
    raise HTTPException(status_code=404, detail="Logo não encontrada no servidor")
