"""
example_output.py
-----------------
Demonstrates IntentGuard's output WITHOUT needing a running server.
Calls risk_engine.score_user() directly so you can verify everything
works before deploying the FastAPI app.

Run:  python example_output.py
"""

import json
import sys
import os

# Ensure we can import project modules
sys.path.insert(0, os.path.dirname(__file__))

try:
    from risk_engine import score_user
except Exception as e:
    print(f"[WARN] Could not load risk engine: {e}")
    print("Run the full pipeline first (run_pipeline.sh) to train the model.")
    sys.exit(1)

EXAMPLES = [
    {
        "label": "Normal developer activity",
        "user":  "alice",
        "events": [
            "ec2:DescribeInstances",
            "s3:GetObject",
            "s3:GetObject",
            "lambda:InvokeFunction",
            "ec2:DescribeInstances",
        ],
        "errors": ["", "", "", "", ""],
    },
    {
        "label": "Multiple access-denied errors",
        "user":  "bob",
        "events": [
            "iam:ListUsers",
            "iam:GetUser",
            "iam:CreateUser",
            "s3:PutObject",
        ],
        "errors": ["AccessDenied", "AccessDenied", "AccessDenied", ""],
    },
    {
        "label": "Privilege escalation pattern",
        "user":  "charlie",
        "events": [
            "iam:CreateUser",
            "iam:AttachUserPolicy",
            "sts:AssumeRole",
            "secretsmanager:GetSecretValue",
        ],
        "errors": ["", "", "", ""],
    },
    {
        "label": "Destructive IAM action",
        "user":  "dave",
        "events": [
            "iam:ListUsers",
            "iam:DeleteUser",
            "iam:DeleteRole",
        ],
        "errors": ["", "", ""],
    },
    {
        "label": "Mass S3 data exfiltration",
        "user":  "eve",
        "events": ["s3:GetObject"] * 15,
        "errors": [""] * 15,
    },
]

DIVIDER = "─" * 60

def run():
    print(f"\n{'═' * 60}")
    print("  IntentGuard — Example Predictions")
    print(f"{'═' * 60}\n")

    for ex in EXAMPLES:
        result = score_user(ex["events"], ex["errors"])
        risk   = result["risk_level"]

        # Simple ANSI colour coding
        colour = {"LOW": "\033[92m", "MEDIUM": "\033[93m", "HIGH": "\033[91m"}.get(risk, "")
        reset  = "\033[0m"

        print(f"{DIVIDER}")
        print(f"  User   : {ex['user']}")
        print(f"  Scenario: {ex['label']}")
        print(f"  Events : {ex['events']}")
        print()
        print(f"  ml_score    : {result['ml_score']:.4f}  (LSTM probability)")
        print(f"  rule_score  : {result['rule_score']:.4f}  (rule-based 0 or 1)")
        print(f"  final_score : {result['final_score']:.4f}  (0.6×ML + 0.4×rules)")
        print(f"  risk_level  : {colour}{risk}{reset}")
        if result["triggered_rules"]:
            print(f"  triggered   : {result['triggered_rules']}")
        print()

    print(f"{DIVIDER}")
    print("\nExpected output summary:")
    print("  alice   → LOW    (routine read operations)")
    print("  bob     → HIGH   (3× AccessDenied)")
    print("  charlie → HIGH   (privilege escalation pattern)")
    print("  dave    → HIGH   (destructive IAM actions)")
    print("  eve     → HIGH   (15× S3 GetObject)")


if __name__ == "__main__":
    run()
