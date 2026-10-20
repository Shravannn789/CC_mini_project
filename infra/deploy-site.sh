#!/usr/bin/env bash
# Deploy the static docs/portfolio site to Amazon S3 behind CloudFront.
#
# What this does:
#   1. creates a private S3 bucket (if it does not exist) and blocks all public access
#   2. syncs site/ into the bucket
#   3. creates a CloudFront Origin Access Control so only the CDN can read the bucket
#   4. creates a CloudFront distribution that redirects HTTP -> HTTPS
#   5. attaches a bucket policy allowing only that distribution to read objects
#
# Requirements: aws CLI v2 with credentials (IAM permission for S3 + CloudFront).
# Usage:
#   export SITE_BUCKET=my-portfolio-site-12345   # must be globally unique
#   export AWS_REGION=us-east-1                 # optional, default us-east-1
#   ./infra/deploy-site.sh
set -euo pipefail

SITE_BUCKET=${SITE_BUCKET:?Set SITE_BUCKET to a globally unique bucket name}
AWS_REGION=${AWS_REGION:-us-east-1}
SITE_DIR=${SITE_DIR:-site}
CALLER_REF="cbv-site-$(date +%s)"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

command -v aws >/dev/null || { echo "error: aws CLI not found (https://aws.amazon.com/cli/)"; exit 1; }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "==> Account: $ACCOUNT_ID  Region: $AWS_REGION  Bucket: $SITE_BUCKET"

echo "==> 1/5 Ensuring bucket exists"
if aws s3api head-bucket --bucket "$SITE_BUCKET" 2>/dev/null; then
  echo "    bucket already exists"
else
  if [ "$AWS_REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$SITE_BUCKET" --region "$AWS_REGION" >/dev/null
  else
    aws s3api create-bucket --bucket "$SITE_BUCKET" --region "$AWS_REGION" \
      --create-bucket-configuration "LocationConstraint=$AWS_REGION" >/dev/null
  fi
  echo "    bucket created"
fi

echo "==> 2/5 Blocking all public access"
aws s3api put-public-access-block --bucket "$SITE_BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null

echo "==> 3/5 Syncing $SITE_DIR/ to s3://$SITE_BUCKET"
aws s3 sync "$SITE_DIR" "s3://$SITE_BUCKET" --delete

echo "==> 4/5 Creating Origin Access Control"
OAC_ID=$(aws cloudfront create-origin-access-control --origin-access-control-config \
  "Name=${CALLER_REF},SigningProtocol=sigv4,SigningBehavior=always,OriginAccessControlOriginType=s3" \
  --query 'OriginAccessControl.Id' --output text)
echo "    OAC: $OAC_ID"

ORIGIN_DOMAIN="${SITE_BUCKET}.s3.${AWS_REGION}.amazonaws.com"
if [ "$AWS_REGION" = "us-east-1" ]; then ORIGIN_DOMAIN="${SITE_BUCKET}.s3.amazonaws.com"; fi

cat > "$TMP_DIR/dist.json" <<EOF
{
  "CallerReference": "${CALLER_REF}",
  "Comment": "Cloud Block Vault docs site",
  "Enabled": true,
  "DefaultRootObject": "index.html",
  "Origins": {
    "Quantity": 1,
    "Items": [
      {
        "Id": "s3-origin",
        "DomainName": "${ORIGIN_DOMAIN}",
        "OriginAccessControlId": "${OAC_ID}",
        "S3OriginConfig": { "OriginAccessIdentity": "" }
      }
    ]
  },
  "DefaultCacheBehavior": {
    "TargetOriginId": "s3-origin",
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": { "Quantity": 2, "Items": ["GET", "HEAD"], "CachedMethods": { "Quantity": 2, "Items": ["GET", "HEAD"] } },
    "ForwardedValues": { "QueryString": false, "Cookies": { "Forward": "none" } },
    "SmoothStreaming": false,
    "Compress": true,
    "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6"
  },
  "PriceClass": "PriceClass_100",
  "ViewerCertificate": { "CloudFrontDefaultCertificate": true },
  "HttpVersion": "http2and3"
}
EOF

echo "==> 5/5 Creating CloudFront distribution (takes ~5 minutes to deploy)"
DIST_JSON=$(aws cloudfront create-distribution --distribution-config "file://$TMP_DIR/dist.json")
DIST_ID=$(echo "$DIST_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Distribution"]["Id"])' 2>/dev/null \
  || echo "$DIST_JSON" | grep -o '"Id": *"[^"]*"' | head -1 | sed 's/.*"Id": *"//; s/"//')
DIST_DOMAIN=$(echo "$DIST_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Distribution"]["DomainName"])' 2>/dev/null \
  || echo "$DIST_JSON" | grep -o '"DomainName": *"[^"]*"' | head -1 | sed 's/.*"DomainName": *"//; s/"//')

cat > "$TMP_DIR/policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudFrontRead",
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${SITE_BUCKET}/*",
      "Condition": {
        "StringEquals": { "AWS:SourceArn": "arn:aws:cloudfront::${ACCOUNT_ID}:distribution/${DIST_ID}" }
      }
    }
  ]
}
EOF
aws s3api put-bucket-policy --bucket "$SITE_BUCKET" --policy "file://$TMP_DIR/policy.json" >/dev/null

echo
echo "Done."
echo "  Distribution ID : $DIST_ID"
echo "  Site URL        : https://${DIST_DOMAIN}"
echo "  Note: the first deployment takes ~5 minutes to propagate; later content"
echo "  updates are visible after an invalidation: ./infra/invalidate.sh $DIST_ID"
