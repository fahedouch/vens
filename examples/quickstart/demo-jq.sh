#!/usr/bin/env bash
# Demo helper for the SecureChainCon talk.
# Replays the jq commands on a vens output: CycloneDX VEX + signed CDXA attestation.
# Usage: ./demo-jq.sh [vex.json] [attestation.json]
set -euo pipefail

VEX="${1:-out.cdx.json}"
ATT="${2:-out.attestation.cdx.json}"

echo "==> rank by contextual OWASP score (real problems on top)"
jq -r '.vulnerabilities[] | [.ratings[0].score, .id] | @tsv' "$VEX" | sort -rn | head

echo
echo "==> how many fall below the action threshold (the noise)"
jq '[.vulnerabilities[] | select(.ratings[0].score < 20)] | length' "$VEX"

echo
echo "==> signed CDXA attestation: evidence behind the verdict"
jq '.' "$ATT" | head -30
