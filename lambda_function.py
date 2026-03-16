"""
lambda_function.py
------------------
AWS Lambda Auto-Healer for S3 bucket misconfigurations.

Triggered by Amazon EventBridge when CloudTrail detects:
  - PutBucketPublicAccessBlock  (disabling public access block)
  - PutBucketPolicy             (applying a public bucket policy)
  - PutBucketAcl                (applying a public ACL)

Remediation actions:
  - Re-enables all four Block Public Access settings
  - Removes public bucket policies
  - Enforces S3 versioning as a bonus control

All actions are logged to CloudWatch for audit purposes.
"""

import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')


def re_enable_block_public_access(bucket_name):
    """Re-enables all four Block Public Access settings on the bucket."""
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls':       True,
            'IgnorePublicAcls':      True,
            'BlockPublicPolicy':     True,
            'RestrictPublicBuckets': True
        }
    )
    logger.info(f"Security Event: PutBucketPublicAccessBlock on {bucket_name}")
    logger.info("Remedied: Public Access Blocked.")


def remove_public_bucket_policy(bucket_name):
    """Removes a public bucket policy."""
    try:
        # Check if policy is actually public before deleting
        status = s3.get_bucket_policy_status(Bucket=bucket_name)
        if status['PolicyStatus'].get('IsPublic', False):
            s3.delete_bucket_policy(Bucket=bucket_name)
            logger.info(f"Security Event: PutBucketPolicy on {bucket_name}")
            logger.info("Remedied: Public bucket policy removed.")
        else:
            logger.info(f"Bucket policy on {bucket_name} is not public. No action needed.")
    except s3.exceptions.NoSuchBucketPolicy:
        logger.info(f"No bucket policy found on {bucket_name}. No action needed.")


def enable_versioning(bucket_name):
    """Enables versioning on the bucket as a bonus security control."""
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': 'Enabled'}
    )
    logger.info(f"Security Event: PutBucketVersioning on {bucket_name}")
    logger.info("Remedied: Versioning Enabled.")


def lambda_handler(event, context):
    """
    Main Lambda handler.
    Receives EventBridge events from CloudTrail and remediates
    S3 bucket misconfigurations.
    """
    try:
        detail     = event.get('detail', {})
        event_name = detail.get('eventName', '')
        params     = detail.get('requestParameters', {})
        bucket_name = params.get('bucketName', '')

        if not bucket_name:
            logger.warning("No bucket name found in event. Skipping.")
            return {'statusCode': 200, 'body': 'No bucket name — skipped.'}

        logger.info(f"Received event: {event_name} on bucket: {bucket_name}")

        # ── Remediation routing ────────────────────────────
        if event_name == 'PutBucketPublicAccessBlock':
            re_enable_block_public_access(bucket_name)
            enable_versioning(bucket_name)

        elif event_name == 'PutBucketPolicy':
            remove_public_bucket_policy(bucket_name)
            re_enable_block_public_access(bucket_name)

        elif event_name == 'PutBucketAcl':
            re_enable_block_public_access(bucket_name)

        else:
            logger.info(f"Event {event_name} not in remediation scope. Skipping.")

        return {
            'statusCode': 200,
            'body': json.dumps(f'Remediation complete for {bucket_name}')
        }

    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}")
        raise e
