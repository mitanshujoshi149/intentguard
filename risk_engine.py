import os, json, logging, torch
from train_lstm import IntentLSTM

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

MODEL_PATH  = os.getenv("MODEL_PATH",  "models/lstm_model.pt")
CONFIG_PATH = os.getenv("CONFIG_PATH", "models/lstm_config.json")
VOCAB_FILE  = os.getenv("VOCAB_FILE",  "data/vocab.json")

ML_WEIGHT   = 0.6
RULE_WEIGHT = 0.4

DENY_THRESHOLD     = 3
S3_EXFIL_THRESHOLD = 10

DESTRUCTIVE_ACTIONS = {"DeleteUser","DeleteRole","DeletePolicy","DeleteGroup","DeleteAccessKey","RemoveUserFromGroup","iam:DeleteUser","iam:DeleteRole","iam:DeletePolicy","iam:DeleteGroup","iam:DeleteAccessKey","iam:RemoveUserFromGroup","s3:DeleteObject","s3:DeleteBucket"}
PRIV_ESC_PRECURSORS = {"CreateUser","AttachUserPolicy","PutUserPolicy","iam:CreateUser","iam:AttachUserPolicy","iam:PutUserPolicy"}
PRIV_ESC_TRIGGER    = {"sts:AssumeRole","AssumeRole"}

SEQ_LEN = int(os.getenv("SEQ_LEN", "30"))

def _load():
    try:
        cfg   = json.load(open(CONFIG_PATH))
        vocab = json.load(open(VOCAB_FILE))
        m = IntentLSTM(vocab_size=cfg["vocab_size"], embed_dim=cfg["embed_dim"], hidden_size=cfg["hidden_size"], num_layers=cfg["num_layers"])
        m.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"))
        m.eval()
        logger.info("LSTM loaded")
        return m, vocab
    except Exception as e:
        logger.warning("Model not loaded: %s", e)
        return None, None

_MODEL, _VOCAB = _load()

def apply_rules(events, errors):
    if sum(1 for e in errors if e == "AccessDenied") >= DENY_THRESHOLD:
        return 1.0
    s = set(events)
    if s & DESTRUCTIVE_ACTIONS: return 1.0
    if (s & PRIV_ESC_PRECURSORS) and (s & PRIV_ESC_TRIGGER): return 1.0
    if sum(1 for e in events if e in ("s3:GetObject","GetObject")) >= S3_EXFIL_THRESHOLD: return 1.0
    return 0.0

def _explain(events, errors):
    t = []; s = set(events)
    d = sum(1 for e in errors if e == "AccessDenied")
    if d >= DENY_THRESHOLD: t.append(f"AccessDenied x{d} (threshold {DENY_THRESHOLD})")
    h = s & DESTRUCTIVE_ACTIONS
    if h: t.append(f"Destructive actions: {chr(44).join(h)}")
    if (s & PRIV_ESC_PRECURSORS) and (s & PRIV_ESC_TRIGGER): t.append("Privilege escalation pattern detected")
    g = sum(1 for e in events if e in ("s3:GetObject","GetObject"))
    if g >= S3_EXFIL_THRESHOLD: t.append(f"High-volume S3 exfiltration: {g} GetObject calls")
    return t

def _encode(events, vocab):
    enc = [vocab.get(e, 1) for e in events[-SEQ_LEN:]]
    return torch.tensor([[0]*(SEQ_LEN-len(enc))+enc], dtype=torch.long)

def _level(s):
    return "HIGH" if s >= 0.70 else "MEDIUM" if s >= 0.40 else "LOW"

def score_user(events, error_codes=None):
    if error_codes is None: error_codes = [""]*len(events)
    rule_score = float(apply_rules(events, error_codes))
    triggered  = _explain(events, error_codes)
    ml_available = _MODEL is not None and _VOCAB is not None
    if ml_available:
        with torch.no_grad():
            ml_score = float(_MODEL(_encode(events, _VOCAB)).item())
    else:
        ml_score = 0.5
    final = ML_WEIGHT * ml_score + RULE_WEIGHT * rule_score
    return {"ml_score":round(ml_score,4), "rule_score":round(rule_score,4), "final_score":round(final,4), "risk_level":_level(final), "triggered_rules":triggered, "ml_available":ml_available}
