#!/bin/bash
# Runs all 4 Trivy scan types and saves output to trivy-scans/
# Author: Mukesh Kumar

set -e

TARGET_IMAGE="nginx:1.21.0"
OUTPUT_DIR="./trivy-scans"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo " Trivy Security Scan — $TARGET_IMAGE"
echo " Timestamp: $TIMESTAMP"
echo "============================================================"

echo ""
echo "[1/4] Scanning IMAGE for CVEs (HIGH + CRITICAL only)..."
trivy image \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --skip-java-db-update \
  --detection-priority comprehensive \
  --skip-version-check \
  --format table \
  --output "$OUTPUT_DIR/01_image_cve_scan.txt" \
  "$TARGET_IMAGE"
echo "[+] Saved: $OUTPUT_DIR/01_image_cve_scan.txt"

echo ""
echo "[2/4] Saving CVE scan as JSON (for pipeline/SIEM use)..."
trivy image \
  --severity HIGH,CRITICAL \
  --skip-java-db-update \
  --detection-priority comprehensive \
  --skip-version-check \
  --format json \
  --output "$OUTPUT_DIR/02_image_cve_scan.json" \
  "$TARGET_IMAGE"
echo "[+] Saved: $OUTPUT_DIR/02_image_cve_scan.json"

echo ""
echo "[3/4] Scanning for SECRETS..."
trivy fs \
  --scanners secret \
  --skip-version-check \
  --format table \
  --output "$OUTPUT_DIR/03_secret_scan.txt" \
  ~/trivy-falco-project/config.env
echo "[+] Saved: $OUTPUT_DIR/03_secret_scan.txt"

echo ""
echo "[4a/4] Scanning DOCKERFILE for misconfigurations..."
trivy config \
  --skip-version-check \
  --format table \
  --output "$OUTPUT_DIR/04_dockerfile_misconfig.txt" \
  ./Dockerfile
echo "[+] Saved: $OUTPUT_DIR/04_dockerfile_misconfig.txt"

echo ""
echo "[4b/4] Scanning K8s MANIFESTS for misconfigurations..."
trivy config \
  --skip-version-check \
  --format table \
  --output "$OUTPUT_DIR/05_k8s_misconfig.txt" \
  ./k8s-manifests/
echo "[+] Saved: $OUTPUT_DIR/05_k8s_misconfig.txt"

echo ""
echo "============================================================"
echo " All scans complete."
ls -lh "$OUTPUT_DIR/"
echo "============================================================"
