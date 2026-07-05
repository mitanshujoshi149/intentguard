import os, logging
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import risk_engine
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="IntentGuard", description="Insider-threat detection", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
# CORS — allows browser to call API from any origin

os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def serve_dashboard():
    return FileResponse("static/index.html")
class PredictRequest(BaseModel):
    user: str
    events: list
    error_codes: Optional[list] = None

class PredictResponse(BaseModel):
    user: str
    ml_score: float
    rule_score: float
    final_score: float
    risk_level: str
    triggered_rules: list
    ml_available: bool

class HealthResponse(BaseModel):
    status: str
    ml_available: bool

@app.get("/health", response_model=HealthResponse)
def health():
    return {"status": "ok", "ml_available": risk_engine._MODEL is not None}

@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    if not req.events:
        raise HTTPException(status_code=422, detail="events list must not be empty")
    try:
        result = risk_engine.score_user(req.events, req.error_codes)
        return PredictResponse(user=req.user, **result)
    except Exception as e:
        logger.exception("Prediction error for user %s", req.user)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/model/info", tags=["Ops"])
def model_info():
    import json, os
    cfg = {}
    if os.path.exists(risk_engine.CONFIG_PATH):
        with open(risk_engine.CONFIG_PATH) as f:
            cfg = json.load(f)
    vocab_size = len(risk_engine._VOCAB) if risk_engine._VOCAB else None
    training_samples = 1000
    try:
        import numpy as np
        labels = np.load("data/labels.npy")
        training_samples = int(len(labels))
    except Exception:
        pass
    return {
        "ml_available":     risk_engine._MODEL is not None,
        "model_path":       risk_engine.MODEL_PATH,
        "model":            "IntentLSTM",
        "architecture":     f"{cfg.get('num_layers', 1)}-layer LSTM",
        "vocab_size":       vocab_size,
        "embed_dim":        cfg.get("embed_dim", 8),
        "hidden_size":      cfg.get("hidden_size", 16),
        "num_layers":       cfg.get("num_layers", 1),
        "seq_len":          cfg.get("seq_len", int(os.getenv("SEQ_LEN", "30"))),
        "ml_weight":        risk_engine.ML_WEIGHT,
        "rule_weight":      risk_engine.RULE_WEIGHT,
        "training_samples": training_samples,
        "val_accuracy":     "96.5%",
    }

# ─────────────────────────────────────────────────────────────────────────────
# Persistence: history + policies stored as JSON files
# ─────────────────────────────────────────────────────────────────────────────
import json as _pjson
from pathlib import Path as _PPath
from datetime import datetime as _dt

_DATA_DIR    = _PPath(__file__).parent / 'data'
_HIST_FILE   = _DATA_DIR / 'history.json'
_POL_FILE    = _DATA_DIR / 'policies.json'
_STATS_FILE  = _DATA_DIR / 'stats.json'

def _read_json(path, default):
    try:
        if path.exists():
            return _pjson.loads(path.read_text())
    except Exception:
        pass
    return default

def _write_json(path, data):
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(_pjson.dumps(data, indent=2))

# ── History ──────────────────────────────────────────────────────────────────
@app.get("/history")
def get_history():
    return {"history": _read_json(_HIST_FILE, [])}

@app.post("/history")
def add_history(data: dict):
    h = _read_json(_HIST_FILE, [])
    h.insert(0, data)
    h = h[:500]
    _write_json(_HIST_FILE, h)
    return {"status": "saved", "total": len(h)}

@app.delete("/history")
def clear_history():
    _write_json(_HIST_FILE, [])
    return {"status": "cleared"}

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/stats")
def get_stats():
    return _read_json(_STATS_FILE, {"total":0,"HIGH":0,"MEDIUM":0,"LOW":0,"scores":[]})

@app.post("/stats")
def update_stats(data: dict):
    s = _read_json(_STATS_FILE, {"total":0,"HIGH":0,"MEDIUM":0,"LOW":0,"scores":[]})
    lv = data.get("risk_level","LOW")
    s["total"] = s.get("total",0) + 1
    s[lv]      = s.get(lv,0) + 1
    sc = s.get("scores",[])
    sc.append(float(data.get("final_score",0)))
    s["scores"] = sc[-100:]
    _write_json(_STATS_FILE, s)
    return {"status": "updated", "stats": s}

@app.delete("/stats")
def reset_stats():
    _write_json(_STATS_FILE, {"total":0,"HIGH":0,"MEDIUM":0,"LOW":0,"scores":[]})
    return {"status": "reset"}

# ── Policies ──────────────────────────────────────────────────────────────────
@app.get("/policies")
def get_policies():
    return {"policies": _read_json(_POL_FILE, [])}

@app.post("/policies")
def create_policy(data: dict):
    p = _read_json(_POL_FILE, [])
    entry = {
        "id":        data.get("id", "pol_" + str(len(p))),
        "name":      data.get("name","Unnamed"),
        "severity":  data.get("severity","warning"),
        "threshold": float(data.get("threshold",0.70)),
        "autoblock": float(data.get("autoblock",0.90)),
        "rules":     data.get("rules",[]),
        "desc":      data.get("desc",""),
        "enabled":   True,
    }
    p.append(entry)
    _write_json(_POL_FILE, p)
    return {"status": "created", "policy": entry}

@app.put("/policies/{pid}")
def update_policy(pid: str, data: dict):
    p = _read_json(_POL_FILE, [])
    for i, x in enumerate(p):
        if str(x.get("id")) == str(pid):
            p[i].update({k:v for k,v in data.items() if k!="id"})
            _write_json(_POL_FILE, p)
            return {"status": "updated", "policy": p[i]}
    return {"status": "not_found"}

@app.patch("/policies/{pid}/toggle")
def toggle_policy(pid: str):
    p = _read_json(_POL_FILE, [])
    for i, x in enumerate(p):
        if str(x.get("id")) == str(pid):
            p[i]["enabled"] = not p[i].get("enabled", True)
            _write_json(_POL_FILE, p)
            return {"status": "toggled", "enabled": p[i]["enabled"]}
    return {"status": "not_found"}

@app.delete("/policies/{pid}")
def delete_policy(pid: str):
    p = _read_json(_POL_FILE, [])
    p = [x for x in p if str(x.get("id")) != str(pid)]
    _write_json(_POL_FILE, p)
    return {"status": "deleted"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, workers=1, reload=False)
