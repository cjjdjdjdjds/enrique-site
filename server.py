# ============================================================
# Enrique RP — сервер
# FastAPI + MySQL + JWT
# ============================================================

import asyncio
import random
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from jose import jwt, JWTError
from pydantic import BaseModel, Field
from sqlalchemy import Column, Integer, String, BigInteger, DateTime, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import select, update

# ============================================================
# НАСТРОЙКИ
# ============================================================

DB_HOST = "188.127.241.8"
DB_PORT = 3306
DB_USER = "gs147741"
DB_PASS = "ZwgzLoactcvs"
DB_NAME = "gs147741"  # если не сработает — попробуй другое имя базы

DB_URL = f"mysql+aiomysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"

SECRET_KEY = "enrique-rp-secret-change-me-in-prod"
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 72

TABLE_NAME = "accounts"  # если сервер ругается, что таблицы нет — попробуй "users"

# ============================================================
# БАЗА ДАННЫХ
# ============================================================

engine = create_async_engine(DB_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()


class Account(Base):
    __tablename__ = TABLE_NAME

    id = Column(Integer, primary_key=True, index=True)
    Name = Column(String(24), unique=True, nullable=False)
    pPass = Column(String(129), nullable=False)
    pLvl = Column(Integer, default=1)
    pAdm = Column(Integer, default=0)
    pAdmWarns = Column(Integer, default=0)
    pLeaderWarns = Column(Integer, default=0)
    pVip = Column(Integer, default=0)
    pVipDays = Column(Integer, default=0)
    pExp = Column(Integer, default=0)
    pCash = Column(BigInteger, default=0)
    pBank = Column(BigInteger, default=0)
    pKills = Column(Integer, default=0)
    pLeader = Column(Integer, default=0)
    pRank = Column(Integer, default=0)
    pMember = Column(Integer, default=0)
    pWarns = Column(Integer, default=0)
    pZakonp = Column(Integer, default=0)


class MinigameLog(Base):
    __tablename__ = "minigame_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, index=True)
    game = Column(String(32))
    bet = Column(BigInteger)
    win = Column(BigInteger)
    created_at = Column(DateTime, default=datetime.utcnow)


async def init_db():
    async with engine.begin() as conn:
        # Проверяем, что таблица accounts существует
        result = await conn.execute(text(f"SHOW TABLES LIKE '{TABLE_NAME}'"))
        if not result.first():
            print(f"[!] Таблица '{TABLE_NAME}' не найдена. Проверь имя таблицы.")
        # Создаём лог мини-игр, если нет
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


# ============================================================
# ПАРОЛИ И ТОКЕНЫ
# ============================================================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_token(user_id: int, name: str) -> str:
    payload = {
        "sub": str(user_id),
        "name": name,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> Account:
    if not credentials:
        raise HTTPException(status_code=401, detail="Нет токена")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Неверный токен")

    result = await db.execute(select(Account).where(Account.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="Игрок не найден")
    return user


# ============================================================
# СХЕМЫ ЗАПРОСОВ
# ============================================================

class RegisterRequest(BaseModel):
    name: str = Field(min_length=3, max_length=20)
    password: str = Field(min_length=6, max_length=64)


class LoginRequest(BaseModel):
    name: str
    password: str


class BetRequest(BaseModel):
    bet: int = Field(gt=0)
    choice: Optional[str] = None  # для монетки / рулетки / угадай


# ============================================================
# ПРИЛОЖЕНИЕ
# ============================================================

app = FastAPI(title="Enrique RP", version="1.0")


@app.on_event("startup")
async def on_startup():
    try:
        await init_db()
        print("[+] База подключена")
    except Exception as e:
        print(f"[!] Ошибка подключения к БД: {e}")


@app.get("/", response_class=HTMLResponse)
async def root():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("<h1>index.html не найден</h1>", status_code=500)


# ---------- АВТОРИЗАЦИЯ ----------

@app.post("/api/register")
async def register(data: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Проверка, есть ли игрок с таким именем
    result = await db.execute(select(Account).where(Account.Name == data.name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Имя уже занято")

    # Создаём нового игрока
    new_acc = Account(
        Name=data.name,
        pPass=hash_password(data.password),
        pLvl=1,
        pCash=1000,   # стартовый капитал
        pBank=0,
    )
    db.add(new_acc)
    await db.commit()
    await db.refresh(new_acc)

    token = create_token(new_acc.id, new_acc.Name)
    return {"ok": True, "token": token, "name": new_acc.Name}


@app.post("/api/login")
async def login(data: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Account).where(Account.Name == data.name))
    user = result.scalar_one_or_none()
    if not user or not verify_password(data.password, user.pPass):
        raise HTTPException(status_code=400, detail="Неверное имя или пароль")

    token = create_token(user.id, user.Name)
    return {"ok": True, "token": token, "name": user.Name}


# ---------- ПРОФИЛЬ ----------

def serialize(user: Account) -> dict:
    return {
        "id": user.id,
        "name": user.Name,
        "level": user.pLvl or 0,
        "exp": user.pExp or 0,
        "cash": user.pCash or 0,
        "bank": user.pBank or 0,
        "total": (user.pCash or 0) + (user.pBank or 0),
        "kills": user.pKills or 0,
        "vip": user.pVip or 0,
        "vip_days": user.pVipDays or 0,
        "admin": user.pAdm or 0,
        "rank": user.pRank or 0,
        "leader": user.pLeader or 0,
        "member": user.pMember or 0,
        "warns": user.pWarns or 0,
        "adm_warns": user.pAdmWarns or 0,
        "leader_warns": user.pLeaderWarns or 0,
        "zakonp": user.pZakonp or 0,
    }


@app.get("/api/me")
async def me(user: Account = Depends(get_current_user)):
    return serialize(user)


@app.get("/api/leaderboard")
async def leaderboard(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Account).order_by(Account.pCash.desc()).limit(10)
    )
    users = result.scalars().all()
    return [
        {"name": u.Name, "cash": u.pCash or 0, "level": u.pLvl or 0}
        for u in users
    ]


# ---------- МИНИ-ИГРЫ ----------

async def update_cash(db: AsyncSession, user_id: int, new_cash: int):
    await db.execute(
        update(Account).where(Account.id == user_id).values(pCash=new_cash)
    )
    await db.commit()


def log_game(db: AsyncSession, user_id: int, game: str, bet: int, win: int):
    return MinigameLog(user_id=user_id, game=game, bet=bet, win=win)


@app.post("/api/game/dice")
async def game_dice(
    data: BetRequest,
    user: Account = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    cash = user.pCash or 0
    if cash < data.bet:
        raise HTTPException(status_code=400, detail="Недостаточно денег")
    if data.bet > cash // 2:
        raise HTTPException(status_code=400, detail="Максимум — половина баланса")

    d1 = random.randint(1, 6)
    d2 = random.randint(1, 6)
    total = d1 + d2

    if total >= 8:
        win = data.bet * 2
        msg = f"Выпало {d1}+{d2}={total}. Победа!"
    elif total >= 5:
        win = data.bet
        msg = f"Выпало {d1}+{d2}={total}. Возврат."
    else:
        win = 0
        msg = f"Выпало {d1}+{d2}={total}. Проигрыш."

    new_cash = cash - data.bet + win
    await update_cash(db, user.id, new_cash)
    db.add(log_game(db, user.id, "dice", data.bet, win))
    await db.commit()

    return {"ok": True, "dice": [d1, d2], "total": total, "win": win, "cash": new_cash, "message": msg}


@app.post("/api/game/coin")
async def game_coin(
    data: BetRequest,
    user: Account = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if data.choice not in ("heads", "tails"):
        raise HTTPException(status_code=400, detail="Выбери heads или tails")

    cash = user.pCash or 0
    if cash < data.bet:
        raise HTTPException(status_code=400, detail="Недостаточно денег")
    if data.bet > cash // 2:
        raise HTTPException(status_code=400, detail="Максимум — половина баланса")

    result = random.choice(["heads", "tails"])
    if result == data.choice:
        win = data.bet * 2
        msg = f"Выпало: {result}. Победа!"
    else:
        win = 0
        msg = f"Выпало: {result}. Проигрыш."

    new_cash = cash - data.bet + win
    await update_cash(db, user.id, new_cash)
    db.add(log_game(db, user.id, "coin", data.bet, win))
    await db.commit()

    return {"ok": True, "result": result, "win": win, "cash": new_cash, "message": msg}


@app.post("/api/game/guess")
async def game_guess(
    data: BetRequest,
    user: Account = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not data.choice or not data.choice.isdigit():
        raise HTTPException(status_code=400, detail="Выбери число 1–10")

    guess = int(data.choice)
    if guess < 1 or guess > 10:
        raise HTTPException(status_code=400, detail="Число от 1 до 10")

    cash = user.pCash or 0
    if cash < data.bet:
        raise HTTPException(status_code=400, detail="Недостаточно денег")
    if data.bet > cash // 2:
        raise HTTPException(status_code=400, detail="Максимум — половина баланса")

    secret = random.randint(1, 10)
    if guess == secret:
        win = data.bet * 5
        msg = f"Загадано {secret}. Угадал! x5"
    else:
        win = 0
        msg = f"Загадано {secret}. Не угадал."

    new_cash = cash - data.bet + win
    await update_cash(db, user.id, new_cash)
    db.add(log_game(db, user.id, "guess", data.bet, win))
    await db.commit()

    return {"ok": True, "secret": secret, "win": win, "cash": new_cash, "message": msg}


@app.post("/api/game/roulette")
async def game_roulette(
    data: BetRequest,
    user: Account = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if data.choice not in ("red", "black", "zero"):
        raise HTTPException(status_code=400, detail="Выбери red, black или zero")

    cash = user.pCash or 0
    if cash < data.bet:
        raise HTTPException(status_code=400, detail="Недостаточно денег")
    if data.bet > cash // 2:
        raise HTTPException(status_code=400, detail="Максимум — половина баланса")

    # 0 = зеро, остальные — красное/чёрное
    roll = random.randint(0, 36)
    if roll == 0:
        result = "zero"
    elif roll % 2 == 0:
        result = "black"
    else:
        result = "red"

    if result == data.choice:
        multiplier = 14 if result == "zero" else 2
        win = data.bet * multiplier
        msg = f"Выпало {roll} ({result}). Победа x{multiplier}!"
    else:
        win = 0
        msg = f"Выпало {roll} ({result}). Проигрыш."

    new_cash = cash - data.bet + win
    await update_cash(db, user.id, new_cash)
    db.add(log_game(db, user.id, "roulette", data.bet, win))
    await db.commit()

    return {"ok": True, "roll": roll, "result": result, "win": win, "cash": new_cash, "message": msg}


# ============================================================
# ЗАПУСК
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
