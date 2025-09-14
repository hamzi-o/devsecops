from fastapi import FastAPI, Request, Response
import hashlib
import subprocess
import base64
import pickle

app = FastAPI(title="Critical Vulnerable Demo API")

# --- Hardcoded secrets ---
API_KEY = "sk-1234567890abcdef"
JWT_SECRET = "super_secret_jwt_key_2024"

# --- Routes with critical vulnerabilities ---

@app.get("/")
def root():
    return {"message": "Critical Vulnerable Demo API"}

# 1. Command Injection (critical, CVSS 9.8)
@app.post("/system")
def system_command(cmd: str):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr}
    except Exception as e:
        return {"error": str(e)}

# 2. Reflected XSS (critical if user input is shown in browser)
@app.get("/greet/{name}")
def greet(name: str):
    return {"message": f"Hello, {name}!"}

# 3. Hardcoded secrets / info disclosure
@app.get("/debug")
def debug_info():
    return {"api_key": API_KEY, "jwt_secret": JWT_SECRET}

# 4. Weak session token
@app.get("/session")
def create_session(username: str):
    token = hashlib.md5(username.encode()).hexdigest()
    return {"session_token": token}

# 5. Deserialization RCE (pickle)
@app.post("/deserialize")
async def deserialize_data(request: Request):
    body = await request.body()
    try:
        data = pickle.loads(base64.b64decode(body))
        return {"deserialized": str(data)}
    except Exception as e:
        return {"error": str(e)}

# 6. SSRF (Server-Side Request Forgery)
@app.get("/fetch")
def fetch_url(url: str):
    import urllib.request
    try:
        with urllib.request.urlopen(url) as response:
            content = response.read().decode()[:500]  # limited content
        return {"content": content}
    except Exception as e:
        return {"error": str(e)}

# 7. Missing auth (admin)
@app.get("/admin")
def admin_access():
    return {"admin_data": "Sensitive admin info", "users": ["admin", "user1"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
