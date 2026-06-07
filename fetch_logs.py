"""
fetch_logs.py
-------------
Downloads CloudTrail JSON logs from an S3 bucket and saves them locally.
Processes files in batches to stay within t2.micro memory limits (~1 GB RAM).
Uses AWS credentials from environment variables or ~/.aws/credentials.
"""

import os
import json
import gzip
import logging
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

S3_BUCKET   = os.getenv("S3_BUCKET", "my-cloudtrail-bucket")
S3_PREFIX   = os.getenv("S3_PREFIX", "AWSLogs/")
LOCAL_DIR   = os.getenv("LOCAL_LOG_DIR", "data/raw")
MAX_FILES   = int(os.getenv("MAX_FILES", "200"))   # cap for t2.micro


def list_log_keys(s3_client, bucket: str, prefix: str, max_files: int) -> list[str]:
    """Return up to max_files .json.gz object keys from S3."""
    keys = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".json.gz"):
                keys.append(key)
                if len(keys) >= max_files:
                    return keys
    return keys


def download_and_extract(s3_client, bucket: str, key: str, dest_dir: str) -> str | None:
    """Download one .json.gz file, extract, and return local path."""
    filename = os.path.basename(key).replace(".gz", "")
    local_path = os.path.join(dest_dir, filename)
    if os.path.exists(local_path):
        logger.info("Already exists, skipping: %s", filename)
        return local_path
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        compressed = response["Body"].read()
        data = gzip.decompress(compressed)
        with open(local_path, "wb") as f:
            f.write(data)
        logger.info("Downloaded: %s", filename)
        return local_path
    except (BotoCoreError, ClientError) as e:
        logger.error("Failed to download %s: %s", key, e)
        return None


def fetch_logs():
    os.makedirs(LOCAL_DIR, exist_ok=True)
    s3 = boto3.client(
        "s3",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION", "us-east-1"),
    )
    logger.info("Listing keys in s3://%s/%s ...", S3_BUCKET, S3_PREFIX)
    keys = list_log_keys(s3, S3_BUCKET, S3_PREFIX, MAX_FILES)
    logger.info("Found %d log files. Downloading...", len(keys))

    success, failed = 0, 0
    for key in keys:
        path = download_and_extract(s3, S3_BUCKET, key, LOCAL_DIR)
        if path:
            success += 1
        else:
            failed += 1

    logger.info("Done. Success=%d  Failed=%d", success, failed)
    return success


# ── Demo mode (no real S3) ───────────────────────────────────────────────────
def generate_sample_logs(n_files: int = 5, events_per_file: int = 40):
    """
    Write synthetic CloudTrail-shaped JSON files so the pipeline runs
    without real AWS credentials.  Called automatically when S3_BUCKET
    is left at the default placeholder value.
    """
    import random, datetime

    os.makedirs(LOCAL_DIR, exist_ok=True)
    users = ["alice", "bob", "charlie", "eve"]
    actions = [
        "s3:GetObject", "s3:PutObject", "ec2:DescribeInstances",
        "iam:ListUsers", "iam:CreateUser", "iam:DeleteUser",
        "sts:AssumeRole", "lambda:InvokeFunction", "rds:DescribeDBInstances",
        "secretsmanager:GetSecretValue",
    ]
    base_ts = datetime.datetime(2024, 1, 1, 0, 0, 0)

    for i in range(n_files):
        records = []
        for j in range(events_per_file):
            ts = base_ts + datetime.timedelta(minutes=i * events_per_file + j)
            records.append({
                "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": random.choice(users),
                },
                "eventName": random.choice(actions),
                "sourceIPAddress": f"192.168.1.{random.randint(1, 20)}",
                "errorCode": "" if random.random() > 0.15 else "AccessDenied",
            })
        payload = {"Records": records}
        path = os.path.join(LOCAL_DIR, f"sample_{i:03d}.json")
        with open(path, "w") as f:
            json.dump(payload, f)
    logger.info("Generated %d sample log files in %s", n_files, LOCAL_DIR)


if __name__ == "__main__":
    if S3_BUCKET == "my-cloudtrail-bucket":
        logger.warning("S3_BUCKET not set — running in DEMO mode with synthetic data.")
        generate_sample_logs()
    else:
        fetch_logs()
