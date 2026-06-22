"""
S3 IAM Access Governance Auditor (with debug logging)
======================================================
Scans IAM users for S3 over-permissioned access.
Audits S3 bucket policies for public access.
Uploads findings as CSV report to S3.

Author: Rahul Kori
Project: AWS Security Auto-Healer + IAM Access Governance (S3 Edition)
"""

import boto3
import json
import csv
import io
from datetime import datetime, timezone, timedelta

# Configuration
INACTIVE_DAYS_THRESHOLD = 90
HIGH_RISK_S3_POLICIES = ['AmazonS3FullAccess', 'AdministratorAccess', 'PowerUserAccess']
REPORT_BUCKET = 'iam-governance-reports-rkori-2026'
SNS_TOPIC_ARN = ''

# AWS clients
iam_client = boto3.client('iam')
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')


def lambda_handler(event, context):
    print(f"[*] Starting S3 IAM Access Governance scan at {datetime.now(timezone.utc).isoformat()}")
    print(f"[DEBUG] Lambda region: {s3_client.meta.region_name}")
    print(f"[DEBUG] REPORT_BUCKET configured as: '{REPORT_BUCKET}'")
    print(f"[DEBUG] Bucket name length: {len(REPORT_BUCKET)} chars")

    findings = []

    users = list_all_users()
    print(f"[*] Found {len(users)} IAM users to audit for S3 access")

    for user in users:
        username = user['UserName']
        user_findings = audit_user_s3_access(username, user)
        if user_findings:
            print(f"[!] User {username}: {len(user_findings)} findings")
            findings.extend(user_findings)

    print(f"\n[*] Auditing S3 bucket policies...")
    bucket_findings = audit_bucket_policies()
    findings.extend(bucket_findings)

    high_severity = [f for f in findings if f['Severity'] == 'HIGH']
    medium_severity = [f for f in findings if f['Severity'] == 'MEDIUM']

    print(f"\n=========================================")
    print(f"S3 IAM ACCESS GOVERNANCE AUDIT COMPLETE")
    print(f"=========================================")
    print(f"Users scanned: {len(users)}")
    print(f"Total findings: {len(findings)}")
    print(f"  HIGH severity: {len(high_severity)}")
    print(f"  MEDIUM severity: {len(medium_severity)}")
    print(f"=========================================\n")

    report_key = upload_report_to_s3(findings)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'service_audited': 'S3',
            'users_scanned': len(users),
            'total_findings': len(findings),
            'high_severity': len(high_severity),
            'medium_severity': len(medium_severity),
            'report_location': f's3://{REPORT_BUCKET}/{report_key}' if report_key else 'no report generated'
        })
    }


def list_all_users():
    users = []
    paginator = iam_client.get_paginator('list_users')
    for page in paginator.paginate():
        users.extend(page['Users'])
    return users


def audit_user_s3_access(username, user_obj):
    findings = []
    findings.extend(check_attached_s3_policies(username))
    findings.extend(check_inline_s3_policies(username))
    findings.extend(check_inactive_user_with_s3(username, user_obj))
    findings.extend(check_mfa_with_s3_access(username))
    return findings


def check_attached_s3_policies(username):
    findings = []
    try:
        response = iam_client.list_attached_user_policies(UserName=username)
        for policy in response['AttachedPolicies']:
            if policy['PolicyName'] in HIGH_RISK_S3_POLICIES:
                findings.append({
                    'User': username,
                    'Severity': 'HIGH',
                    'RuleName': 'OVER_PRIVILEGED_S3_POLICY',
                    'Resource': 'S3',
                    'Detail': f"User has high-risk policy: {policy['PolicyName']}",
                    'Remediation': f"Replace {policy['PolicyName']} with least-privilege policy."
                })
    except Exception as e:
        print(f"[!] Error checking attached policies for {username}: {e}")
    return findings


def check_inline_s3_policies(username):
    findings = []
    try:
        policy_names = iam_client.list_user_policies(UserName=username)['PolicyNames']
        for policy_name in policy_names:
            policy_doc = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)['PolicyDocument']
            statements = policy_doc.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            for stmt in statements:
                if stmt.get('Effect') != 'Allow':
                    continue
                actions = stmt.get('Action', [])
                resources = stmt.get('Resource', [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                has_s3_wildcard = any(a == 's3:*' or a == '*' for a in actions)
                has_wildcard_resource = '*' in resources
                if has_s3_wildcard and has_wildcard_resource:
                    findings.append({
                        'User': username,
                        'Severity': 'HIGH',
                        'RuleName': 'WILDCARD_S3_INLINE_POLICY',
                        'Resource': 'S3',
                        'Detail': f"Inline policy '{policy_name}' grants s3:* with Resource:*",
                        'Remediation': "Replace wildcards with specific actions and ARNs."
                    })
    except Exception as e:
        print(f"[!] Error checking inline policies for {username}: {e}")
    return findings


def check_inactive_user_with_s3(username, user_obj):
    findings = []
    threshold_date = datetime.now(timezone.utc) - timedelta(days=INACTIVE_DAYS_THRESHOLD)
    try:
        password_last_used = user_obj.get('PasswordLastUsed')
        if password_last_used and password_last_used < threshold_date:
            days_inactive = (datetime.now(timezone.utc) - password_last_used).days
            findings.append({
                'User': username,
                'Severity': 'MEDIUM',
                'RuleName': 'INACTIVE_USER',
                'Resource': 'S3',
                'Detail': f"User inactive for {days_inactive} days",
                'Remediation': "Review and remove access for inactive users."
            })
    except Exception as e:
        print(f"[!] Error checking activity for {username}: {e}")
    return findings


def check_mfa_with_s3_access(username):
    findings = []
    try:
        mfa_devices = iam_client.list_mfa_devices(UserName=username)['MFADevices']
        try:
            iam_client.get_login_profile(UserName=username)
            has_console_access = True
        except iam_client.exceptions.NoSuchEntityException:
            has_console_access = False
        if has_console_access and not mfa_devices:
            findings.append({
                'User': username,
                'Severity': 'MEDIUM',
                'RuleName': 'NO_MFA',
                'Resource': 'S3',
                'Detail': "User has console access but no MFA",
                'Remediation': "Enforce MFA on all console accounts."
            })
    except Exception as e:
        print(f"[!] Error checking MFA for {username}: {e}")
    return findings


def audit_bucket_policies():
    findings = []
    try:
        buckets = s3_client.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                policy_str = s3_client.get_bucket_policy(Bucket=bucket_name)['Policy']
                policy_doc = json.loads(policy_str)
                statements = policy_doc.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]
                for stmt in statements:
                    if stmt.get('Effect') != 'Allow':
                        continue
                    principal = stmt.get('Principal', {})
                    is_public = False
                    if principal == '*':
                        is_public = True
                    elif isinstance(principal, dict):
                        for value in principal.values():
                            if value == '*' or (isinstance(value, list) and '*' in value):
                                is_public = True
                    if is_public:
                        findings.append({
                            'User': 'BUCKET_POLICY',
                            'Severity': 'HIGH',
                            'RuleName': 'PUBLIC_BUCKET_POLICY',
                            'Resource': bucket_name,
                            'Detail': "Bucket policy allows Principal: * (public)",
                            'Remediation': "Restrict Principal to specific accounts."
                        })
            except Exception:
                continue
    except Exception as e:
        print(f"[!] Error: {e}")
    return findings


def upload_report_to_s3(findings):
    if not findings:
        print("[*] No findings to report.")
        return None

    # DEBUG: Print bucket details before attempting upload
    print(f"[DEBUG] Attempting to upload report to bucket: '{REPORT_BUCKET}'")
    print(f"[DEBUG] Bucket name length: {len(REPORT_BUCKET)} chars")
    print(f"[DEBUG] S3 client region: {s3_client.meta.region_name}")

    # DEBUG: Test if bucket exists and is accessible
    try:
        s3_client.head_bucket(Bucket=REPORT_BUCKET)
        print(f"[DEBUG] Bucket exists and is accessible from this Lambda")
    except Exception as e:
        print(f"[DEBUG] Bucket head_bucket check failed: {type(e).__name__}: {e}")

    # DEBUG: List all buckets visible to this Lambda
    try:
        all_buckets = s3_client.list_buckets()
        print(f"[DEBUG] Buckets visible to Lambda:")
        for b in all_buckets['Buckets']:
            print(f"[DEBUG]   - '{b['Name']}' (created: {b['CreationDate']})")
    except Exception as e:
        print(f"[DEBUG] Could not list buckets: {e}")

    csv_buffer = io.StringIO()
    fieldnames = ['User', 'Severity', 'RuleName', 'Resource', 'Detail', 'Remediation']
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    writer.writerows(findings)

    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')
    report_key = f"s3-iam-governance-reports/{timestamp}_audit.csv"

    try:
        s3_client.put_object(
            Bucket=REPORT_BUCKET,
            Key=report_key,
            Body=csv_buffer.getvalue(),
            ContentType='text/csv'
        )
        print(f"[+] Report uploaded: s3://{REPORT_BUCKET}/{report_key}")
        return report_key
    except Exception as e:
        print(f"[!] Failed to upload report: {e}")
        return None
