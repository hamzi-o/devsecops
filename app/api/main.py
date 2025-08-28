from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Adaptive DevSecOps Demo")

class Echo(BaseModel):
    data: dict | None = None

@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "devsecops-demo"}

@app.get("/greet/{name}")
def greet(name: str):
    return {"message": f"Hello, {name}!"}

@app.post("/echo")
def echo(payload: Echo):
    return {"echo": payload.data or {}}

@app.get("/items/{item_id}")
def get_item(item_id: int):
    return {"item_id": item_id, "ok": True}

@app.get("/admin")
def admin():
    raise HTTPException(status_code=403, detail="Forbidden")
