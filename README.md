# S3 Security Auto-Healer

An event-driven, self-healing AWS security pipeline that automatically detects and remediates S3 bucket misconfigurations in near-real time — reducing Mean Time To Remediate (MTTR) from minutes to milliseconds.

---

## Architecture

```
IAM User/Admin
      │
      │  Disables Block Public Access / Applies public policy
      ▼
  S3 Bucket  ──── API call logged ────►  AWS CloudTrail
                                               │
                                               │  Event forwarded
                                               ▼
                                       Amazon EventBridge
                                       (Rule: PutBucketPublicAccessBlock
                                              PutBucketPolicy
                                              PutBucketAcl)
                                               │
                                               │  Triggers
                                               ▼
                                        AWS Lambda
                                     (Auto-Healer function)
                                          │        │
                          Re-enables      │        │  Logs audit
                          Block Public    │        │  trail
                          Access          │        ▼
                                          │   CloudWatch Logs
                                          │
                                          ▼
                                      S3 Bucket
                                   (Secured — not public)
```

---

## How It Works

1. An IAM user or admin introduces a misconfiguration — disabling Block Public Access or applying a public bucket policy
2. AWS CloudTrail captures the API call as an event within seconds
3. Amazon EventBridge matches the event against a rule and fires the Lambda function
4. AWS Lambda re-enables all four Block Public Access settings and removes any public bucket policy
5. Amazon CloudWatch Logs records the full remediation audit trail
6. The bucket is secured — it was never publicly accessible for more than milliseconds

---

## Security Controls Enforced

| Control | Implementation |
|---|---|
| Block Public ACLs | Re-enabled by Lambda on every trigger |
| Ignore Public ACLs | Re-enabled by Lambda on every trigger |
| Block Public Policy | Re-enabled by Lambda on every trigger |
| Restrict Public Buckets | Re-enabled by Lambda on every trigger |
| S3 Versioning | Enabled automatically as a bonus control |
| Audit Trail | Every remediation logged to CloudWatch |

---

## Framework Alignment

| Framework | Control | Mapping |
|---|---|---|
| NIST CSF | Detect (DE.CM-3) | CloudTrail + EventBridge detecting misconfiguration |
| NIST CSF | Respond (RS.MI-1) | Lambda auto-remediating within milliseconds |
| NIST CSF | Recover (RC.RP-1) | Bucket restored to secure state automatically |
| CIS AWS Foundations Benchmark | Control 2.1.5 | S3 Block Public Access enabled |
| OWASP Cloud Top 10 | C7 | Insecure cloud storage remediated |

---

## Repository Structure

```
s3-security-auto-healer/
│
├── README.md                  ← This file
├── simulate_attack.py         ← Simulates S3 misconfiguration for testing
├── lambda_function.py         ← Lambda Auto-Healer function code
├── eventbridge_rule.json      ← EventBridge rule configuration
├── lambda_iam_policy.json     ← IAM policy for Lambda execution role
├── requirements.txt           ← Python dependencies
├── .gitignore                 ← Excludes credentials and cache files
└── screenshots/               ← Evidence of working pipeline
    ├── cloudwatch_logs.png
    ├── architecture_diagram.png
    └── remediation_result.png
```

---

## Setup Guide

### Prerequisites

- AWS account with CloudTrail enabled
- Python 3.8+ installed locally
- AWS CLI configured (`aws configure`)
- Boto3 installed (`pip install boto3`)

---

### Step 1 — Enable CloudTrail

```
AWS Console → CloudTrail → Create Trail
→ Trail name: s3-security-trail
→ Log bucket: create new
→ Enable for all regions: Yes
→ Management events: Read + Write
→ Create trail
```

CloudTrail must be enabled for EventBridge to receive S3 API events.

---

### Step 2 — Deploy the Lambda Function

```
AWS Console → Lambda → Create Function
→ Function name: S3-Security-Auto-Healer
→ Runtime: Python 3.11
→ Architecture: x86_64
→ Create function
→ Paste contents of lambda_function.py into the code editor
→ Deploy
```

---

### Step 3 — Attach IAM Policy to Lambda

```
AWS Console → IAM → Roles
→ Find your Lambda execution role (created in Step 2)
→ Add permissions → Create inline policy
→ Paste contents of lambda_iam_policy.json
→ Name: S3AutoHealerPolicy
→ Create policy
```

---

### Step 4 — Create EventBridge Rule

```
AWS Console → EventBridge → Rules → Create Rule
→ Name: S3-Security-Auto-Healer-Rule
→ Event bus: default
→ Rule type: Rule with an event pattern
→ Event pattern: paste contents of eventbridge_rule.json
→ Target: Lambda function → S3-Security-Auto-Healer
→ Create rule
```

---

### Step 5 — Run the Simulation

```bash
# Clone the repo
git clone https://github.com/your-username/s3-security-auto-healer.git
cd s3-security-auto-healer

# Install dependencies
pip install -r requirements.txt

# Update BUCKET_NAME and REGION in simulate_attack.py
# Then run the simulation
python simulate_attack.py
```

---

### Expected Output

```
=======================================================
   S3 Security Auto-Healer — Attack Simulation
=======================================================

[*] Step 1: Verifying bucket: rahul-final-lab-2026
[!] Bucket already exists. Proceeding...

[*] Step 2: Disabling bucket-level Block Public Access...
[+] Bucket-level block disabled.

[*] Step 3: Simulating misconfiguration — applying public bucket policy...
[+] Public bucket policy applied. Misconfiguration introduced.
[!] CloudTrail has captured the event.
[!] EventBridge rule should now fire Lambda Auto-Healer...

--- IMMEDIATE STATUS (before Lambda remediation) ---
[🚨] Bucket is PUBLIC — misconfiguration confirmed.
     Public Policy : True
     Block Active  : False

[*] Step 4: Waiting for Auto-Healer Lambda to remediate...
    [~] Checking remediation status... attempt 1/15
    [~] Checking remediation status... attempt 2/15
    [+] Remediation confirmed on attempt 2!

=======================================================
   FINAL SECURITY VERIFICATION RESULT
=======================================================

[✅] SUCCESS — Auto-Healer Lambda worked correctly.

     Bucket        : rahul-final-lab-2026
     Public Policy : False   ← private
     Block Active  : True    ← protected

[🔒] BUCKET IS NOT PUBLIC.
     Misconfiguration detected and remediated
     automatically by the Lambda Auto-Healer pipeline.

[+] Check CloudWatch logs for full remediation audit trail.
=======================================================
```

---

## CloudWatch Log Evidence

The Lambda function logs every security event and remediation action:

```
Security Event: PutBucketPublicAccessBlock on rahul-final-lab-2026
Remedied: Public Access Blocked.

Security Event: PutBucketPolicy on rahul-final-lab-2026
Remedied: Public bucket policy removed.

Security Event: PutBucketVersioning on rahul-final-lab-2026
Remedied: Versioning Enabled.
```

---

## Key Metrics

| Metric | Value |
|---|---|
| Mean Time To Detect (MTTD) | < 5 seconds (CloudTrail + EventBridge) |
| Mean Time To Remediate (MTTR) | < 1 second (Lambda execution) |
| Lambda execution time | ~370–392 ms (per CloudWatch logs) |
| Lambda memory used | 103 MB of 128 MB allocated |
| Misconfigurations detected | PutBucketPublicAccessBlock, PutBucketPolicy, PutBucketAcl |

---

## Technologies Used

- **AWS Lambda** — serverless remediation function
- **Amazon EventBridge** — event routing and rule matching
- **AWS CloudTrail** — API call logging and event capture
- **Amazon CloudWatch Logs** — audit trail and monitoring
- **Amazon S3** — target resource being protected
- **Python 3.11** — Lambda runtime
- **Boto3** — AWS SDK for Python

---

## Author

**Rahul Rajkumar Kori**
Masters in Cybersecurity Risk Management — Indiana University
[LinkedIn](https://linkedin.com/in/rahul-kori) | [GitHub](https://github.com/rahul-kori)

---

## License

MIT License — free to use and modify for educational purposes.
