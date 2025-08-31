from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime, func, ForeignKey, or_
)
from sqlalchemy.orm import sessionmaker, Session, declarative_base

from jose import JWTError, jwt
from passlib.context import CryptContext

app = FastAPI(title="Mini Bank — Auth, States, Limits, Transactions")

import os

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./bank.db")
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PROD")


# ===== Config =====
SQLALCHEMY_DATABASE_URL = "sqlite:///./bank.db"
SECRET_KEY = "CHANGE_ME_TO_A_RANDOM_LONG_SECRET"  # <- replace in prod
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24h

# ===== DB Setup =====
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ===== Security Helpers =====
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
http_bearer = HTTPBearer()  # gives "Authorize" button in Swagger

def hash_password(p: str) -> str:
    return pwd_context.hash(p)

def verify_password(p: str, hashed: str) -> bool:
    return pwd_context.verify(p, hashed)

def create_access_token(subject: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = {"sub": subject, "exp": datetime.utcnow() + timedelta(minutes=expires_minutes)}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ===== ORM Models =====
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False, index=True)
    email = Column(String, nullable=True)
    balance = Column(Float, nullable=False, default=0.0)
    state = Column(String, nullable=False, default="active")  # active|frozen|closed
    daily_limit = Column(Float, nullable=False, default=1000.0)
    interest_rate = Column(Float, nullable=False, default=0.01)  # 1% annual
    last_interest_date = Column(DateTime, nullable=True)  # instead of server_default=func.now()
    created_at = Column(DateTime, server_default=func.now())

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True)
    type = Column(String, nullable=False)  # deposit|transfer
    amount = Column(Float, nullable=False)
    from_account_id = Column(Integer, ForeignKey("accounts.id"), nullable=True)
    to_account_id = Column(Integer, ForeignKey("accounts.id"), nullable=True)
    memo = Column(String, nullable=False, default="")
    created_at = Column(DateTime, server_default=func.now())

# ===== Pydantic Models =====
class RegisterIn(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1)
    password: str = Field(min_length=6)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AccountCreate(BaseModel):
    name: str = Field(min_length=1)
    initial_deposit: float = Field(default=0, ge=0)
    email: Optional[EmailStr] = None

class Deposit(BaseModel):
    account_id: int
    amount: float = Field(gt=0)
    memo: Optional[str] = ""

class Transfer(BaseModel):
    from_id: int
    to_id: int
    amount: float = Field(gt=0)
    memo: Optional[str] = ""

class LimitUpdate(BaseModel):
    daily_limit: float = Field(gt=0)

# ===== DB Dependency =====
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ===== Auth Dependency =====
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
    db: Session = Depends(get_db),
) -> User:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return user

# ===== Helpers =====
def must_acc(db: Session, aid: int) -> Account:
    acc = db.query(Account).filter(Account.id == aid).first()
    if not acc:
        raise HTTPException(status_code=404, detail=f"Account {aid} not found")
    return acc

def ensure_active(acc: Account, *, for_receive: bool = False):
    if acc.state != "active":
        role = "receiver" if for_receive else "sender"
        raise HTTPException(status_code=400, detail=f"Account {acc.id} ({role}) is {acc.state}")

def sent_today(db: Session, aid: int) -> float:
    total = (
        db.query(func.coalesce(func.sum(Transaction.amount), 0.0))
        .filter(
            Transaction.type == "transfer",
            Transaction.from_account_id == aid,
            func.date(Transaction.created_at) == func.date(func.current_timestamp()),
        )
        .scalar()
    )
    return float(total or 0.0)

def log_tx(db: Session, **kwargs) -> Transaction:
    tx = Transaction(**kwargs)
    db.add(tx)
    db.commit()
    db.refresh(tx)
    return tx

def tx_to_dict(tx: Transaction):
    return {
        "id": tx.id,
        "type": tx.type,
        "amount": tx.amount,
        "from_account_id": tx.from_account_id,
        "to_account_id": tx.to_account_id,
        "memo": tx.memo,
        "created_at": tx.created_at,
    }

# ===== Startup =====
@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

# ===== Public endpoints: register & login =====
@app.post("/auth/register", response_model=TokenOut)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=body.email, name=body.name, password_hash=hash_password(body.password))
    db.add(user); db.commit(); db.refresh(user)
    token = create_access_token(subject=user.email)
    return TokenOut(access_token=token)

@app.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(subject=user.email)
    return TokenOut(access_token=token)

@app.get("/auth/me")
def me(current: User = Depends(get_current_user)):
    return {"id": current.id, "email": current.email, "name": current.name, "created_at": current.created_at}

# ===== Accounts =====
@app.post("/accounts")
def create_account(body: AccountCreate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    new_account = Account(
        user_id=current.id,
        name=body.name,
        email=body.email,
        balance=float(body.initial_deposit),
    )
    db.add(new_account); db.commit(); db.refresh(new_account)

    if body.initial_deposit and body.initial_deposit > 0:
        log_tx(
            db,
            type="deposit",
            amount=float(body.initial_deposit),
            from_account_id=None,
            to_account_id=new_account.id,
            memo="Initial deposit",
        )

    return {
        "account_id": new_account.id,
        "name": new_account.name,
        "email": new_account.email,
        "balance": new_account.balance,
        "state": new_account.state,
        "daily_limit": new_account.daily_limit,
        "owner_user_id": new_account.user_id,
    }

@app.get("/my/accounts")
def my_accounts(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    rows = db.query(Account).where(Account.user_id == current.id).order_by(Account.id).all()
    return [
        {
            "account_id": a.id,
            "name": a.name,
            "email": a.email,
            "balance": a.balance,
            "state": a.state,
            "daily_limit": a.daily_limit,
        }
        for a in rows
    ]

@app.get("/accounts/{account_id}")
def read_account(account_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    acc = must_acc(db, account_id)
    if acc.user_id != current.id:
        raise HTTPException(status_code=403, detail="Not your account")
    return {
        "account_id": acc.id,
        "name": acc.name,
        "email": acc.email,
        "balance": acc.balance,
        "state": acc.state,
        "daily_limit": acc.daily_limit,
        "created_at": acc.created_at,
    }

@app.get("/accounts/{account_id}/balance")
def read_balance(account_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    acc = must_acc(db, account_id)
    if acc.user_id != current.id:
        raise HTTPException(status_code=403, detail="Not your account")
    return {"account_id": acc.id, "balance": acc.balance}

# ===== Money movement =====
@app.post("/deposit")
def deposit(body: Deposit, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    acc = must_acc(db, body.account_id)
    if acc.user_id != current.id:
        raise HTTPException(status_code=403, detail="Not your account")
    ensure_active(acc, for_receive=True)
    acc.balance += float(body.amount)
    db.add(acc); db.commit()
    log_tx(
        db,
        type="deposit",
        amount=float(body.amount),
        from_account_id=None,
        to_account_id=acc.id,
        memo=body.memo or "Deposit",
    )
    db.refresh(acc)
    return {"account_id": acc.id, "balance": acc.balance}

@app.post("/transfer")
def transfer(body: Transfer, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    if body.from_id == body.to_id:
        raise HTTPException(status_code=400, detail="from_id and to_id must be different")

    from_acc = must_acc(db, body.from_id)
    to_acc = must_acc(db, body.to_id)

    # Only the OWNER of the from-account can send
    if from_acc.user_id != current.id:
        raise HTTPException(status_code=403, detail="You can only send from your own account")

    # Receiver can be anyone, but both must be active
    ensure_active(from_acc)
    ensure_active(to_acc, for_receive=True)

    # Daily limit check
    already = sent_today(db, from_acc.id)
    if already + body.amount > from_acc.daily_limit:
        remaining = max(0.0, from_acc.daily_limit - already)
        raise HTTPException(status_code=400, detail=f"Daily limit exceeded. Remaining today: {remaining:.2f}")

    if from_acc.balance < body.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    # Post transfer
    from_acc.balance -= float(body.amount)
    to_acc.balance += float(body.amount)
    db.add(from_acc); db.add(to_acc); db.commit()

    tx = log_tx(
        db,
        type="transfer",
        amount=float(body.amount),
        from_account_id=from_acc.id,
        to_account_id=to_acc.id,
        memo=body.memo or "Transfer",
    )

    return {
        "status": "posted",
        "from_id": from_acc.id,
        "to_id": to_acc.id,
        "amount": float(body.amount),
        "from_balance": from_acc.balance,
        "to_balance": to_acc.balance,
        "tx_id": tx.id,
    }

# ===== Transactions & Admin actions =====
@app.get("/accounts/{account_id}/transactions")
def account_transactions(account_id: int, limit: int = 50, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    acc = must_acc(db, account_id)
    if acc.user_id != current.id:
        raise HTTPException(status_code=403, detail="Not your account")
    txs = (
        db.query(Transaction)
        .filter(or_(Transaction.from_account_id == account_id,
                    Transaction.to_account_id == account_id))
        .order_by(Transaction.id.desc())
        .limit(limit)
        .all()
    )
    return [tx_to_dict(t) for t in txs]

@app.patch("/accounts/{account_id}/freeze")
def freeze_account(account_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    acc = must_acc(db, account_id)
    if acc.user_id != current.id:
        raise HTTPException(status_code=403, detail="Not your account")
    acc.state = "frozen"; db.add(acc); db.commit(); db.refresh(acc)
    return {"account_id": acc.id, "state": acc.state}

@app.patch("/accounts/{account_id}/unfreeze")
def unfreeze_account(account_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    acc = must_acc(db, account_id)
    if acc.user_id != current.id:
        raise HTTPException(status_code=403, detail="Not your account")
    acc.state = "active"; db.add(acc); db.commit(); db.refresh(acc)
    return {"account_id": acc.id, "state": acc.state}

@app.patch("/accounts/{account_id}/close")
def close_account(account_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    acc = must_acc(db, account_id)
    if acc.user_id != current.id:
        raise HTTPException(status_code=403, detail="Not your account")
    if acc.balance != 0:
        raise HTTPException(status_code=400, detail="Balance must be zero to close account")
    acc.state = "closed"; db.add(acc); db.commit(); db.refresh(acc)
    return {"account_id": acc.id, "state": acc.state}

@app.patch("/accounts/{account_id}/limit")
def set_limit(account_id: int, body: LimitUpdate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    acc = must_acc(db, account_id)
    if acc.user_id != current.id:
        raise HTTPException(status_code=403, detail="Not your account")
    acc.daily_limit = float(body.daily_limit)
    db.add(acc); db.commit(); db.refresh(acc)
    return {"account_id": acc.id, "daily_limit": acc.daily_limit}

# ===== Audit =====
@app.get("/audit/trial_balance")
def trial_balance(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    total_accounts = db.query(func.coalesce(func.sum(Account.balance), 0.0)).scalar()
    total_deposits = db.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(Transaction.type == "deposit").scalar()
    total_transfers = db.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(Transaction.type == "transfer").scalar()
    return {
        "total_in_accounts": float(total_accounts or 0.0),
        "total_deposited": float(total_deposits or 0.0),
        "total_transferred": float(total_transfers or 0.0),
        "note": "Bank snapshot for audit visibility",
    }

from datetime import date, datetime

@app.post("/jobs/apply_interest")
def apply_interest(db: Session = Depends(get_db)):
    today = date.today()
    accounts = db.query(Account).filter(Account.state == "active").all()
    applied = []

    for acc in accounts:
        # Apply if never applied OR last applied before today
        if acc.last_interest_date and acc.last_interest_date.date() >= today:
            continue

        daily_rate = acc.interest_rate / 365.0
        interest_amt = acc.balance * daily_rate

        if interest_amt > 0:
            acc.balance += interest_amt
            acc.last_interest_date = datetime.utcnow()
            db.add(acc)
            db.add(Transaction(
                type="interest",
                amount=interest_amt,
                from_account_id=None,
                to_account_id=acc.id,
                memo="Daily interest credit"
            ))
            db.commit()
            db.refresh(acc)
            applied.append({"account_id": acc.id, "interest": interest_amt})

    return {"applied": applied, "note": "Daily interest job"}


@app.post("/jobs/apply_fees")
def apply_fees(db: Session = Depends(get_db)):
    accounts = db.query(Account).filter(Account.state == "active").all()
    applied = []

    for acc in accounts:
        if acc.balance < 100:  # Example: balance under $100
            fee = 5.0
            if acc.balance >= fee:
                acc.balance -= fee
                db.add(acc)
                tx = Transaction(
                    type="fee",
                    amount=fee,
                    from_account_id=acc.id,
                    to_account_id=None,
                    memo="Low balance fee"
                )
                db.add(tx)
                db.commit()
                db.refresh(acc)
                applied.append({"account_id": acc.id, "fee": fee})

    return {"applied": applied, "note": "Fee job run"}
