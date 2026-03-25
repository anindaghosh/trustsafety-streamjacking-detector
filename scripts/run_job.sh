#!/bin/bash
set -euo pipefail

GCS_BUCKET="${GCS_BUCKET:?GCS_BUCKET env var is required}"
RISK_THRESHOLD="${RISK_THRESHOLD:-10}"
MAX_RESULTS="${MAX_RESULTS:-30}"
RESULTS_DIR="/app/data/results"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")

echo "========================================================"
echo " Streamjacking Detector — Cloud Run Job"
echo " Run timestamp: ${TIMESTAMP}"
echo "========================================================"

# 1. Run the detector
python src/youtube_streamjacking_detector_enhanced.py \
    --max-results "${MAX_RESULTS}" \
    --risk-threshold "${RISK_THRESHOLD}"

# 2. Upload JSON results to GCS
echo ""
echo "Uploading results to GCS..."

MAIN_JSON="${RESULTS_DIR}/streamjacking_detection_results.json"
HIGH_RISK_JSON="${RESULTS_DIR}/high_risk_channels.json"

if [ -f "${MAIN_JSON}" ]; then
    gsutil cp "${MAIN_JSON}" "gs://${GCS_BUCKET}/runs/${TIMESTAMP}/streamjacking_detection_results.json"
    gsutil cp "${MAIN_JSON}" "gs://${GCS_BUCKET}/latest/streamjacking_detection_results.json"
    echo "Uploaded main results to gs://${GCS_BUCKET}/runs/${TIMESTAMP}/"
else
    echo "WARNING: Main results file not found, skipping GCS upload"
fi

if [ -f "${HIGH_RISK_JSON}" ]; then
    gsutil cp "${HIGH_RISK_JSON}" "gs://${GCS_BUCKET}/runs/${TIMESTAMP}/high_risk_channels.json"
    gsutil cp "${HIGH_RISK_JSON}" "gs://${GCS_BUCKET}/latest/high_risk_channels.json"
fi

# 3. Run post-processing analysis (non-fatal)
if [ -f "${MAIN_JSON}" ]; then
    echo ""
    echo "Running post-processing analysis..."
    python src/analysis.py "${MAIN_JSON}" || echo "WARNING: analysis.py failed (non-fatal)"
fi

echo ""
echo "Job complete. Results at gs://${GCS_BUCKET}/runs/${TIMESTAMP}/"
