#!/usr/bin/env bash
# Consumer-side gate: verify signature + SBOM attestation + SLSA provenance before deploy.
# Usage: supplychain/verify.sh ghcr.io/org/security-api@sha256:...
set -euo pipefail
IMAGE="${1:?usage: verify.sh <image@digest>}"
IDENTITY_RE="${COSIGN_IDENTITY_RE:-https://github.com/.*/.github/workflows/supply-chain.yml@.*}"
OIDC="${COSIGN_OIDC:-https://token.actions.githubusercontent.com}"

echo "[*] verifying keyless signature"
cosign verify "$IMAGE" \
  --certificate-identity-regexp "$IDENTITY_RE" \
  --certificate-oidc-issuer "$OIDC"

echo "[*] verifying CycloneDX SBOM attestation"
cosign verify-attestation "$IMAGE" --type cyclonedx \
  --certificate-identity-regexp "$IDENTITY_RE" \
  --certificate-oidc-issuer "$OIDC"

echo "[*] verifying SLSA provenance"
cosign verify-attestation "$IMAGE" --type slsaprovenance \
  --certificate-identity-regexp ".*slsa-github-generator.*" \
  --certificate-oidc-issuer "$OIDC"

echo "[ok] all supply-chain gates passed for $IMAGE"
