from fastapi import FastAPI, Request
import hashlib
import subprocess
import base64
import pickle
import urllib.request

app = FastAPI(title="Critical Vulnerable Demo API")

# Hardcoded secrets
API_KEY = "sk-1234567890abcdef"
JWT_SECRET = "super_secret_jwt_key_2024"

@app.get("/")
def root():
    return {"message": "Critical Vulnerable Demo API"}

# Reflected XSS
@app.get("/greet/{name}")
def greet(name: str):
    return {"message": f"Hello, {name}!"}

# Info disclosure
@app.get("/debug")
def debug_info():
    return {"api_key": API_KEY, "jwt_secret": JWT_SECRET}

# Weak session token
@app.get("/session")
def create_session(username: str):
    token = hashlib.md5(username.encode()).hexdigest()
    return {"session_token": token}

# Command injection (safe runtime)
@app.post("/system")
def system_command(cmd: str):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return {"output": result.stdout, "error": result.stderr}
    except Exception as e:
        return {"error": str(e)}

# Deserialization RCE (only triggers on request)
@app.post("/deserialize")
async def deserialize_data(request: Request):
    body = await request.body()
    try:
        data = pickle.loads(base64.b64decode(body))
        return {"deserialized": str(data)}
    except Exception as e:
        return {"error": str(e)}

# SSRF
@app.get("/fetch")
def fetch_url(url: str):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            content = response.read().decode()[:500]
        return {"content": content}
    except Exception as e:
        return {"error": str(e)}

# Missing authentication
@app.get("/admin")
def admin_access():
    return {"admin_data": "Sensitive admin info", "users": ["admin", "user1"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
