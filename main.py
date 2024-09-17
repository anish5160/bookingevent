from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional, List
from datetime import datetime, timedelta

# Configuration Constants
SECRET_KEY = "bb0fa77b71cce8b28bac8f761930deada53601b65bca912148279f589239bd02"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database Setup
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://root:anish@localhost/your_database_name"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    full_name = Column(String(100))
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(255))
    disabled = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100))
    date = Column(DateTime)
    location = Column(String(100))
    capacity = Column(Integer)
    available_slots = Column(Integer)

class Booking(Base):
    __tablename__ = "bookings"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    event_id = Column(Integer, ForeignKey("events.id"))
    user = relationship("UserDB")
    event = relationship("Event")

Base.metadata.create_all(bind=engine)

# Pydantic Schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    username: str
    full_name: Optional[str] = None
    email: str
    password: str

class EventBase(BaseModel):
    name: str
    date: datetime
    location: str
    capacity: int

class EventCreate(EventBase):
    pass

class EventResponse(EventBase):
    id: int
    available_slots: int

    class Config:
        orm_mode = True

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI App
app = FastAPI()

# Helper Functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserDB:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def is_admin(user: UserDB) -> bool:
    return user.is_admin

# Routes
@app.post("/register/")
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    is_admin_flag = user.email == "admin@example.com"

    db_user = UserDB(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=pwd_context.hash(user.password),
        is_admin=is_admin_flag
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    if db_user.is_admin:
        return {"msg": "User registered successfully", "redirect_to": "/admin"}
    else:
        return {"msg": "User registered successfully", "redirect_to": "/user"}



@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user.username})

    # Return different response based on role
    if user.is_admin:
        return {"access_token": access_token, "token_type": "bearer", "message": "Welcome Admin", "admin_dashboard_url": "/admin"}
    else:
        return {"access_token": access_token, "token_type": "bearer", "message": "Welcome User", "user_dashboard_url": "/user"}

@app.post("/events/", response_model=EventResponse)
async def create_event(event: EventCreate, db: Session = Depends(get_db), user: UserDB = Depends(get_current_user)):
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Not authorized to create an event")
    
    db_event = Event(**event.dict(), available_slots=event.capacity)
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event

@app.put("/events/{event_id}/")
async def update_event(event_id: int, event: EventCreate, db: Session = Depends(get_db), user: UserDB = Depends(get_current_user)):
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Not authorized")

    db_event = db.query(Event).filter(Event.id == event_id).first()
    if not db_event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    for key, value in event.dict().items():
        setattr(db_event, key, value)
    
    db.commit()
    db.refresh(db_event)
    return db_event


@app.delete("/events/{event_id}/")
async def delete_event(event_id: int, db: Session = Depends(get_db), user: UserDB = Depends(get_current_user)):
    # Check if the user is an admin
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Not authorized")

    # Check if the event exists
    db_event = db.query(Event).filter(Event.id == event_id).first()
    if not db_event:
        raise HTTPException(status_code=404, detail="Event not found")

    try:
        # Check if there are related bookings that need to be handled
        related_bookings = db.query(Booking).filter(Booking.event_id == event_id).all()
        if related_bookings:
            # If there are related bookings, handle them (e.g., delete or notify)
            for booking in related_bookings:
                db.delete(booking)

        # Delete the event
        db.delete(db_event)
        db.commit()

        return {"detail": "Event deleted successfully"}
    
    except Exception as e:
        # Roll back the session in case of any errors
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")



@app.post("/events/{event_id}/book/")
async def book_event(event_id: int, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    db_event = db.query(Event).filter(Event.id == event_id).first()
    if not db_event:
        raise HTTPException(status_code=404, detail="Event not found")
    if db_event.available_slots <= 0:
        raise HTTPException(status_code=400, detail="No available slots")

    user = get_current_user(token=token, db=db)
    if user:
        booking = Booking(user_id=user.id, event_id=event_id)
        db.add(booking)
        db_event.available_slots -= 1
        db.commit()
        return {"detail": "Event booked successfully"}
    else:
        raise HTTPException(status_code=401, detail="Invalid user")
