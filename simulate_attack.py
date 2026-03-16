"""
simulate_attack.py
------------------
Simulates an S3 bucket misconfiguration by applying a public
bucket policy — triggering the Auto-Healer Lambda pipeline.

Usage:
    python simulate_attack.py

Requirements:
    pip install boto3
    AWS credentials configured via ~/.aws/credentials or environment variables.
"""

import boto3
import json
import time
from botocore.exceptions import ClientError

# ── Configuration ──────────────────────────────────────────
BUCKET_NAME = "rahul-final-lab-2026"
REGION      = "us-east-2"
# ───────────────────────────────────────────────────────────

s3 = boto3.client('s3', region_name=REGION)


def check_public_status():
    """Returns (is_public_policy, block_active) tuple."""
    try:
        status = s3.get_bucket_policy_status(Bucket=BUCKET_NAME)
        is_public_policy = status['PolicyStatus'].get('IsPublic', False)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            is_public_policy = False
        else:
            raise e

    try:
        pab    = s3.get_public_access_block(Bucket=BUCKET_NAME)
        config = pab['PublicAccessBlockConfiguration']
        block_active = all([
            config.get('BlockPublicAcls',        False),
            config.get('IgnorePublicAcls',       False),
            config.get('BlockPublicPolicy',      False),
            config.get('RestrictPublicBuckets',  False),
        ])
    except ClientError:
        block_active = False

    return is_public_policy, block_active


def run_simulation():
    try:
        print("=" * 55)
        print("   S3 Security Auto-Healer — Attack Simulation")
        print("=" * 55)

        # ── Step 1: Create / verify bucket ────────────────
        print(f"\n[*] Step 1: Verifying bucket: {BUCKET_NAME}")
        try:
            s3.create_bucket(
                Bucket=BUCKET_NAME,
                CreateBucketConfiguration={'LocationConstraint': REGION}
            )
            print("[+] Bucket created successfully.")
        except s3.exceptions.BucketAlreadyOwnedByYou:
            print("[!] Bucket already exists. Proceeding...")

        # ── Step 2: Disable bucket-level Block Public Access ──
        print("\n[*] Step 2: Disabling bucket-level Block Public Access...")
        s3.put_public_access_block(
            Bucket=BUCKET_NAME,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls':       False,
                'IgnorePublicAcls':      False,
                'BlockPublicPolicy':     False,
                'RestrictPublicBuckets': False
            }
        )
        print("[+] Bucket-level block disabled.")
        time.sleep(2)

        # ── Step 3: Introduce misconfiguration ────────────
        print("\n[*] Step 3: Simulating misconfiguration — applying public bucket policy...")
        public_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid":       "PublicReadGetObject",
                "Effect":    "Allow",
                "Principal": "*",
                "Action":    "s3:GetObject",
                "Resource":  f"arn:aws:s3:::{BUCKET_NAME}/*"
            }]
        })
        s3.put_bucket_policy(Bucket=BUCKET_NAME, Policy=public_policy)
        print("[+] Public bucket policy applied. Misconfiguration introduced.")
        print("[!] CloudTrail has captured the event.")
        print("[!] EventBridge rule should now fire Lambda Auto-Healer...")

        # ── Step 4: Immediate status check ────────────────
        print("\n--- IMMEDIATE STATUS (before Lambda remediation) ---")
        is_public_policy, block_active = check_public_status()
        if is_public_policy:
            print("[🚨] Bucket is PUBLIC — misconfiguration confirmed.")
            print(f"     Public Policy : {is_public_policy}")
            print(f"     Block Active  : {block_active}")
        else:
            print("[~] Lambda may have already remediated. Waiting to confirm...")

        # ── Step 5: Poll for Lambda remediation ───────────
        print("\n[*] Step 4: Waiting for Auto-Healer Lambda to remediate...")
        remediated = False
        for attempt in range(1, 16):
            time.sleep(2)
            print(f"    [~] Checking remediation status... attempt {attempt}/15")
            is_public_policy, block_active = check_public_status()
            if not is_public_policy and block_active:
                remediated = True
                print(f"    [+] Remediation confirmed on attempt {attempt}!")
                break

        # ── Step 6: Final result ───────────────────────────
        print("\n" + "=" * 55)
        print("   FINAL SECURITY VERIFICATION RESULT")
        print("=" * 55)

        if remediated:
            print(f"\n[✅] SUCCESS — Auto-Healer Lambda worked correctly.")
            print(f"\n     Bucket        : {BUCKET_NAME}")
            print(f"     Public Policy : {is_public_policy}   ← private")
            print(f"     Block Active  : {block_active}  ← protected")
            print(f"\n[🔒] BUCKET IS NOT PUBLIC.")
            print( "     Misconfiguration detected and remediated")
            print( "     automatically by the Lambda Auto-Healer pipeline.")
            print(f"\n[+] Check CloudWatch logs for full remediation audit trail.")
        else:
            print(f"\n[⚠️]  Lambda did not remediate within 30 seconds.")
            print(f"     Public Policy : {is_public_policy}")
            print(f"     Block Active  : {block_active}")
            print( "\n     Check EventBridge rule and Lambda function logs.")

        print("\n" + "=" * 55)

    except ClientError as e:
        print(f"\n[X] AWS API Error: {e}")
    except Exception as e:
        print(f"\n[X] Unexpected Error: {e}")


if __name__ == "__main__":
    run_simulation()
