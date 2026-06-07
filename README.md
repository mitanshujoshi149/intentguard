# IntentGuard — AWS Insider Threat Detection

Real-time insider threat detection system for AWS cloud environments using hybrid LSTM + Rule Engine approach.

## Live Demo
http://54.90.145.193:8000

## Architecture
## Features
- 2-layer LSTM neural network (96.5% validation accuracy)
- Hybrid scoring: 0.6 × ML + 0.4 × Rules
- Detects: Privilege Escalation, Data Exfiltration, Destructive Actions, Brute Force
- Real-time SOC dashboard with attack chain visualization
- Persistent prediction history via AWS S3
- 10 REST API endpoints

## Tech Stack
- **ML**: PyTorch, LSTM, NumPy
- **Backend**: Python, FastAPI, Uvicorn, Pydantic
- **Frontend**: HTML5, CSS3, JavaScript
- **Cloud**: AWS EC2, S3, CloudTrail, IAM

## API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Server health check |
| GET | /model/info | Model metadata |
| POST | /predict | Single prediction |
| POST | /predict/batch | Batch prediction |
| GET | /history | Prediction history |
| GET | /policies | Detection policies |

## Setup
```bash
git clone https://github.com/joshi_mitanshu/intentguard.git
cd intentguard
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Model Performance
- Training samples: 1000
- Validation accuracy: 96.5%
- Architecture: 2-layer LSTM, embed_dim=64, hidden=128
- Epochs: 20

## Detection Rules
- Privilege Escalation: iam:CreateUser + sts:AssumeRole
- Data Exfiltration: 10+ s3:GetObject calls
- Destructive Actions: s3:DeleteObject, iam:DeleteUser
- Brute Force: 3+ AccessDenied errors
