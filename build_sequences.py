import os, csv, json, logging, numpy as np
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PARSED_CSV = os.getenv("PARSED_CSV", "data/parsed_logs.csv")
SEQ_LEN    = int(os.getenv("SEQ_LEN", "30"))
OUT_SEQ    = "data/sequences.npy"
OUT_LABELS = "data/labels.npy"
OUT_VOCAB  = "data/vocab.json"
OUT_USERS  = "data/user_index.json"
VOCAB_FILE = OUT_VOCAB

DENY_THRESHOLD     = 3
S3_EXFIL_THRESHOLD = 10

DESTRUCTIVE_ACTIONS = {
    "DeleteUser", "DeleteRole", "DeletePolicy", "DeleteGroup",
    "DeleteAccessKey", "RemoveUserFromGroup",
    "iam:DeleteUser", "iam:DeleteRole", "iam:DeletePolicy", "iam:DeleteGroup",
    "iam:DeleteAccessKey", "iam:RemoveUserFromGroup",
    "s3:DeleteObject", "s3:DeleteBucket",
}

PRIV_ESC_PRECURSORS = {
    "CreateUser", "AttachUserPolicy", "PutUserPolicy",
    "iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy",
}

PRIV_ESC_TRIGGER = {"sts:AssumeRole", "AssumeRole"}


def apply_rules(events, errors):
    if sum(1 for e in errors if e == "AccessDenied") >= DENY_THRESHOLD:
        return 1.0
    s = set(events)
    if s & DESTRUCTIVE_ACTIONS:
        return 1.0
    if (s & PRIV_ESC_PRECURSORS) and (s & PRIV_ESC_TRIGGER):
        return 1.0
    if sum(1 for e in events if e in ("s3:GetObject", "GetObject")) >= S3_EXFIL_THRESHOLD:
        return 1.0
    return 0.0


def build_sequences():
    if not os.path.exists(PARSED_CSV):
        raise FileNotFoundError(f"{PARSED_CSV} not found.")
    ue = defaultdict(list)
    uerr = defaultdict(list)
    vocab = {"<PAD>": 0, "<UNK>": 1}
    with open(PARSED_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ue[row["user"]].append(row["event_name"])
            uerr[row["user"]].append(row["error_code"])
            if row["event_name"] not in vocab:
                vocab[row["event_name"]] = len(vocab)
    users  = sorted(ue.keys())
    seqs   = np.zeros((len(users), SEQ_LEN), dtype=np.int32)
    labels = np.zeros(len(users), dtype=np.float32)
    for i, u in enumerate(users):
        enc = [vocab.get(e, 1) for e in ue[u][-SEQ_LEN:]]
        seqs[i] = [0] * (SEQ_LEN - len(enc)) + enc
        labels[i] = apply_rules(ue[u], uerr[u])
    os.makedirs("data", exist_ok=True)
    np.save(OUT_SEQ, seqs)
    np.save(OUT_LABELS, labels)
    with open(OUT_VOCAB, "w") as f:
        json.dump(vocab, f, indent=2)
    with open(OUT_USERS, "w") as f:
        json.dump({str(i): u for i, u in enumerate(users)}, f, indent=2)
    logger.info("Done.")


if __name__ == "__main__":
    build_sequences()
