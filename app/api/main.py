from fastapi import FastAPI, HTTPException
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel
import hashlib
import subprocess

app = FastAPI(title="Adaptive DevSecOps Demo")
app = FastAPI(title="Light Vulnerable DevSecOps Demo API")

class Echo(BaseModel):
    data: dict | None = None
# --- Hardcoded secrets ---
DATABASE_PASSWORD = "admin123!@#"
API_KEY = "sk-1234567890abcdef"
JWT_SECRET = "super_secret_jwt_key_2024"

# --- Pydantic models ---
class CommandRequest(BaseModel):
    command: str

# --- Routes ---
@app.get("/")
def root():
    return {"message": "Welcome to the Adaptive DevSecOps Demo API"}

    return {"message": "Welcome to the Lightweight Vulnerable Demo API"}

@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "devsecops-demo"}
    return {"status": "ok"}

@app.get("/greet/{name}")
def greet(name: str):
    # Reflected XSS
    return {"message": f"Hello, {name}!"}

@app.post("/echo")
def echo(payload: Echo):
    return {"echo": payload.data or {}}

@app.get("/items/{item_id}")
def get_item(item_id: int):
    return {"item_id": item_id, "ok": True}
@app.post("/system")
def system_command(cmd: CommandRequest):
    # Command Injection
    try:
        result = subprocess.run(cmd.command, shell=True, capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr}
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug")
def debug_info():
    # Information Disclosure
    return {"database_password": DATABASE_PASSWORD, "api_key": API_KEY}

@app.get("/session")
def create_session(username: str):
    # Weak session token
    token = hashlib.md5(username.encode()).hexdigest()
    return {"session_token": token}

@app.get("/admin")
def admin():
    raise HTTPException(status_code=403, detail="Forbidden")
def admin_access():
    # Missing authentication
    return {"admin_data": "Sensitive admin information", "users": ["admin", "user1"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
