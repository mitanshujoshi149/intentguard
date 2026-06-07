#!/bin/bash
# =============================================================================
# IntentGuard — full pipeline runner
# Run this once to go from raw S3 logs → trained model → live API
# =============================================================================
set -euo pipefail

echo "============================================================"
echo "  IntentGuard Pipeline"
echo "============================================================"

# ── 0. Setup ──────────────────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
  cp .env.template .env
  echo "[0] .env created from template. Edit it before running with real AWS creds."
fi

echo ""
echo "[1/5] Installing dependencies..."
pip install -q -r requirements.txt

echo ""
echo "[2/5] Fetching / generating logs..."
python fetch_logs.py

echo ""
echo "[3/5] Parsing logs..."
python parse_logs.py

echo ""
echo "[4/5] Building sequences..."
python build_sequences.py

echo ""
echo "[5/5] Training LSTM..."
python train_lstm.py

echo ""
echo "============================================================"
echo "  Pipeline complete! Starting API server..."
echo "  POST to http://localhost:8000/predict to score users."
echo "  Docs at   http://localhost:8000/docs"
echo "============================================================"
echo ""
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
