
from fastapi import FastAPI, Form, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from database import get_db, engine, Base
from models import User
from security import hash_password, verify_password

app = FastAPI(title="Login System")

# Create database tables
Base.metadata.create_all(bind=engine)

# Static and template folders
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


# Home page
@app.get("/")
def home():
    return RedirectResponse(url="/login", status_code=303)


# Login page
@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None}
    )


# Register page
@app.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"error": None}
    )


# Register API
@app.post("/register")
def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(
        User.email == email
    ).first()

    if existing_user:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Email already registered"}
        )

    if len(password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Password must contain at least 8 characters"}
        )

    new_user = User(
        email=email,
        password_hash=hash_password(password)
    )

    db.add(new_user)
    db.commit()

    return RedirectResponse(
        url="/login?registered=true",
        status_code=303
    )


# Login API
@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.email == email
    ).first()

    if user is None or not verify_password(
        password, user.password_hash
    ):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid email or password"}
        )

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"email": user.email}
    )
