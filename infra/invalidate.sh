#!/usr/bin/env bash
# Invalidate CloudFront cache after re-uploading site content.
# Usage: ./infra/invalidate.sh <distribution-id> [path]   (default path: /*)
set -euo pipefail

DIST_ID=${1:?Usage: ./infra/invalidate.sh <distribution-id> [path]}
PATH_TO_CLEAR=${2:-/*}

command -v aws >/dev/null || { echo "error: aws CLI not found"; exit 1; }

INVALIDATION_ID=$(aws cloudfront create-invalidation --distribution-id "$DIST_ID" \
  --paths "$PATH_TO_CLEAR" --query 'Invalidation.Id' --output text)
echo "Invalidation $INVALIDATION_ID started for $DIST_ID ($PATH_TO_CLEAR)"
echo "Track it with: aws cloudfront get-invalidation --distribution-id $DIST_ID --id $INVALIDATION_ID"
