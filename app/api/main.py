from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import hashlib
import subprocess
import os
import json
import base64
import secrets
from typing import Optional

app = FastAPI(title="Enhanced Vulnerable DevSecOps Demo API")

# --- CORS Vulnerability: Overly permissive CORS policy ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Vulnerable: Allows any origin
    allow_credentials=True,
    allow_methods=["*"],  # Vulnerable: Allows all HTTP methods
    allow_headers=["*"],
)

# --- Hardcoded secrets (Secret Disclosure) ---
DATABASE_PASSWORD = "admin123!@#"
API_KEY = "sk-1234567890abcdef"
JWT_SECRET = "super_secret_jwt_key_2024"
ADMIN_TOKEN = "admin_secret_token_2024"
AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
STRIPE_SECRET = "sk_test_1234567890abcdef"

# Global session store (vulnerable implementation)
active_sessions = {}

# --- Pydantic models ---
class Echo(BaseModel):
    data: dict | None = None

class CommandRequest(BaseModel):
    command: str

class UserLogin(BaseModel):
    username: str
    password: str

class FileRequest(BaseModel):
    filename: str

class AdminCommand(BaseModel):
    token: str
    action: str
    params: dict = {}

# --- Basic Routes ---
@app.get("/")
def root():
    return {"message": "Welcome to the Enhanced Vulnerable DevSecOps Demo API"}

@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "enhanced-devsecops-demo"}

# --- XSS Vulnerabilities ---
@app.get("/greet/{name}", response_class=HTMLResponse)
def greet(name: str):
    # Reflected XSS - renders user input directly in HTML
    html_content = f"""
    <html>
        <head><title>Greeting</title></head>
        <body>
            <h1>Hello, {name}!</h1>
            <p>Welcome to our vulnerable demo site!</p>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/search")
def search(q: str):
    # Reflected XSS in JSON response
    return {"query": q, "results": f"Search results for: {q}"}

@app.post("/comment")
def add_comment(request: Request, comment: dict):
    # Stored XSS simulation - would store in real database
    return {
        "message": "Comment added successfully",
        "comment": comment.get("text", ""),
        "preview": f"<div>User comment: {comment.get('text', '')}</div>"
    }

@app.get("/profile/{user_id}")
def get_profile(user_id: str, bio: Optional[str] = None):
    # DOM-based XSS potential
    return {
        "user_id": user_id,
        "bio": bio or "No bio provided",
        "script": f"<script>var userId = '{user_id}';</script>"
    }

# --- Command Injection Vulnerabilities ---
@app.post("/system")
def system_command(cmd: CommandRequest):
    # OS Command Injection
    try:
        result = subprocess.run(cmd.command, shell=True, capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr, "command": cmd.command}
    except Exception as e:
        return {"error": str(e)}

@app.get("/ping/{host}")
def ping_host(host: str):
    # Command injection via path parameter
    try:
        command = f"ping -c 3 {host}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return {"host": host, "result": result.stdout}
    except Exception as e:
        return {"error": str(e)}

@app.post("/backup")
def create_backup(file_req: FileRequest):
    # Command injection in file operations
    try:
        backup_cmd = f"tar -czf backup_{file_req.filename}.tar.gz {file_req.filename}"
        result = subprocess.run(backup_cmd, shell=True, capture_output=True, text=True)
        return {"message": "Backup created", "filename": file_req.filename}
    except Exception as e:
        return {"error": str(e)}

# --- Secret Disclosure Vulnerabilities ---
@app.get("/debug")
def debug_info():
    # Information Disclosure - secrets exposed
    return {
        "database_password": DATABASE_PASSWORD,
        "api_key": API_KEY,
        "jwt_secret": JWT_SECRET,
        "aws_key": AWS_ACCESS_KEY,
        "stripe_key": STRIPE_SECRET
    }

@app.get("/config")
def get_config():
    # Environment variables disclosure
    return {
        "environment": dict(os.environ),
        "app_config": {
            "debug": True,
            "secret_key": JWT_SECRET,
            "database_url": "postgresql://admin:admin123@localhost/vulnerable_db"
        }
    }

@app.get("/source")
def get_source():
    # Source code disclosure
    try:
        with open(__file__, 'r') as f:
            return {"source_code": f.read()}
    except Exception as e:
        return {"error": str(e)}

@app.get("/.env")
def env_file():
    # Simulated .env file exposure
    env_content = """
DATABASE_PASSWORD=admin123!@#
API_KEY=sk-1234567890abcdef
JWT_SECRET=super_secret_jwt_key_2024
AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_test_1234567890abcdef
    """.strip()
    return Response(content=env_content, media_type="text/plain")

# --- Session Management Vulnerabilities ---
@app.post("/login")
def login(user_login: UserLogin):
    # Weak session token generation
    if user_login.username and user_login.password:
        # MD5 hash of username (predictable)
        session_token = hashlib.md5(user_login.username.encode()).hexdigest()
        
        # Session fixation vulnerability - accept any session ID
        active_sessions[session_token] = {
            "username": user_login.username,
            "role": "admin" if user_login.username == "admin" else "user"
        }
        
        return {
            "session_token": session_token,
            "username": user_login.username,
            "message": "Login successful"
        }
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/session/{session_id}")
def get_session_info(session_id: str):
    # Session token validation vulnerability
    # Accepts any format, predictable tokens
    if session_id in active_sessions:
        return active_sessions[session_id]
    
    # Weak token generation for demo
    fake_session = {
        "username": "demo_user",
        "role": "user",
        "token_type": "weak_md5"
    }
    active_sessions[session_id] = fake_session
    return fake_session

@app.post("/session/fixate")
def fixate_session(request: Request):
    # Session fixation vulnerability
    session_id = request.headers.get("X-Session-ID", "default_session")
    
    active_sessions[session_id] = {
        "username": "anonymous",
        "role": "user",
        "fixed": True
    }
    
    return {"session_id": session_id, "message": "Session created"}

# --- Insecure HTTP Methods ---
@app.api_route("/admin/users", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"])
def admin_users(request: Request):
    # Accepts all HTTP methods without proper validation
    method = request.method
    
    if method == "TRACE":
        # TRACE method vulnerability
        return Response(
            content=f"TRACE {request.url}\n" + "\n".join([f"{k}: {v}" for k, v in request.headers.items()]),
            media_type="message/http"
        )
    
    return {
        "method": method,
        "message": f"Admin endpoint accessed via {method}",
        "users": ["admin", "user1", "user2"] if method == "GET" else "Operation completed"
    }

@app.options("/admin/sensitive")
def sensitive_options():
    # Overly permissive OPTIONS response
    return Response(
        headers={
            "Allow": "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*"
        }
    )

# --- Additional Vulnerabilities ---
@app.post("/upload")
def upload_file(request: Request, filename: str):
    # File upload without validation
    return {
        "message": f"File {filename} uploaded successfully",
        "path": f"/uploads/{filename}",
        "executable": filename.endswith(('.sh', '.bat', '.exe', '.py'))
    }

@app.get("/redirect")
def open_redirect(url: str):
    # Open redirect vulnerability
    return JSONResponse(
        content={"message": "Redirecting..."},
        headers={"Location": url, "Refresh": f"0; url={url}"}
    )

@app.post("/admin/execute")
def admin_execute(admin_cmd: AdminCommand):
    # Insecure admin functionality
    if admin_cmd.token == ADMIN_TOKEN:
        if admin_cmd.action == "system":
            cmd = admin_cmd.params.get("command", "whoami")
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                return {"output": result.stdout, "error": result.stderr}
            except Exception as e:
                return {"error": str(e)}
        
        return {"message": f"Admin action '{admin_cmd.action}' executed"}
    
    raise HTTPException(status_code=403, detail="Invalid admin token")

# --- Information Disclosure ---
@app.get("/logs")
def get_logs():
    # Log file exposure
    fake_logs = [
        "2024-01-15 10:30:25 - Admin login from 192.168.1.100",
        "2024-01-15 10:31:45 - Database query: SELECT * FROM users WHERE password='admin123'",
        "2024-01-15 10:32:10 - API key used: sk-1234567890abcdef",
        "2024-01-15 10:33:22 - Error: JWT token validation failed for user admin",
        "2024-01-15 10:34:15 - Backup created with admin credentials"
    ]
    return {"logs": fake_logs}

@app.get("/version")
def version_info():
    # Version disclosure
    return {
        "app_version": "1.0.0-vulnerable",
        "framework": "FastAPI 0.104.1",
        "python_version": "3.11.5",
        "dependencies": {
            "uvicorn": "0.24.0",
            "pydantic": "2.5.0"
        },
        "build_info": {
            "build_date": "2024-01-15",
            "git_commit": "abc123def456",
            "debug_mode": True
        }
    }

# --- Echo endpoint ---
@app.post("/echo")
def echo(payload: Echo):
    return {"echo": payload.data or {}}

@app.get("/items/{item_id}")
def get_item(item_id: int):
    return {"item_id": item_id, "ok": True}

if __name__ == "__main__":
    import uvicorn
    print("⚠️  WARNING: This is a vulnerable application for educational purposes only!")
    print("⚠️  Do NOT deploy this in production or on public networks!")
    uvicorn.run(app, host="0.0.0.0", port=8000)
