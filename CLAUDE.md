# CLAUDE.md — Streamjacking Detector

## Project Overview

NYU Trust & Safety (CS-UY 3943) research project. Detects YouTube "stream-jacking" — fraudulent live streams that impersonate celebrities or brands to run crypto scams.

**Team:** Aninda Ghosh (ag10293@nyu.edu), Dhari Alshammari (da3974@nyu.edu)
**Instructor:** Prof. Rosanna Bellini

---

## Architecture

### Main Components

| File | Role |
|------|------|
| `src/youtube_streamjacking_detector_enhanced.py` | Primary detector — YouTube API client, signal scoring, MongoDB writer |
| `src/cryptobert_signal.py` | Signal 12: fine-tuned CryptoBERT classifier (optional, loaded at runtime) |
| `src/finetune_cryptobert.py` | One-time fine-tuning script for CryptoBERT |
| `src/analysis.py` | Post-run statistical analysis on collected JSON results |
| `src/signal_analysis.py` | Per-signal breakdown and metrics |
| `src/calculate_metrics.py` | Precision/recall/F1 against validated labels |
| `src/validation_helper.py` / `src/interactive_validator.py` | Manual labeling tools |
| `src/retroactive_ato_classification.py` | Classifies account takeover (ATO) type retroactively |
| `src/export_training_data.py` | Exports labeled data for CryptoBERT fine-tuning |

### Supporting Scripts

| File | Role |
|------|------|
| `src/backup_mongodb.py` / `src/backup_mongo.py` | MongoDB backup utilities |
| `src/deduplicate_collection.py` | Remove duplicate MongoDB documents |
| `src/sync_validations_to_mongodb.py` | Sync CSV labels back to MongoDB |
| `src/correct_validations.py` | Fix mislabeled validation entries |
| `src/redetect_collection.py` | Re-run detector signals on stored documents |
| `src/backfill_descriptions.py` | Backfill missing video descriptions via API |
| `src/verify_active_videos.py` | Check if previously detected videos are still live |
| `src/query_video.py` | One-off lookup of a single video |
| `src/generate_visualizations.py` | Charts for analysis reports |

---

## Environment Setup

```bash
# Install dependencies
pip install -r requirements.txt --break-system-packages

# Required env var
export YOUTUBE_API_KEY='your-api-key-here'

# Optional (for MongoDB storage)
export MONGODB_URI='mongodb+srv://...'

# Copy and fill in .env.template -> .env
cp .env.template .env
```

The detector uses `python-dotenv` — a `.env` file in the project root is loaded automatically.

---

## Running the Detector

```bash
# Basic run (defaults: max-results=50, risk-threshold=30)
python src/youtube_streamjacking_detector_enhanced.py

# With options
python src/youtube_streamjacking_detector_enhanced.py --max-results 30 --risk-threshold 10

# Run post-processing analysis on saved results
python src/analysis.py data/results/streamjacking_detection_results.json
```

Output files land in `data/results/`:
- `streamjacking_detection_results.json` — all detections
- `high_risk_channels.json` — risk score >= threshold

---

## Detection Signals (16 total)

**Channel-level:**
1. Character substitution impersonation (l→I, O→0)
2. Account age vs. activity mismatch
3. Subscriber/content disparity
4. Handle-name mismatch
5. Hidden subscriber count
6. Crypto-heavy description

**Video-level:**
7. Title impersonation
8. Scam keywords (giveaway, double, send)
9. Crypto wallet addresses / suspicious URLs
10. Urgency language
11. High-confidence scam phrases
12. **CryptoBERT classifier** (fine-tuned; requires model artifacts)
13. Disabled comments
14. Live stream status
15. Engagement anomalies (high views + restricted comments)
16. Suspicious domains

**Risk thresholds:** High >= 70, Medium 40–69, Low < 40
**Total score formula:** `video_risk + (channel_risk × 0.5)`

---

## CryptoBERT Model

Fine-tuned model artifacts live at `data/models/cryptobert-streamjacking/`. The training checkpoint subdirectories (~3.8 GB) are excluded from Docker — only inference artifacts are included:
- `config.json`, `model.safetensors`, `tokenizer.json`, `tokenizer_config.json`
- `training_args.bin`, `calibration.json`, `training_results.json`

If the model directory is absent, Signal 12 is silently skipped.

---

## Docker / Cloud Run Deployment

```bash
# Build image (CPU-only PyTorch)
docker build -t detector .

# Run locally
docker run -e YOUTUBE_API_KEY=... -e GCS_BUCKET=... -e MONGODB_URI=... detector

# Cloud Build + Cloud Run Jobs (CI/CD)
# See cloudbuild.yaml — triggered on push, deploys to Cloud Run Job: streamjacking-detector-job
# Region: us-east1
```

Key env vars for the container:
- `YOUTUBE_API_KEY` — required
- `GCS_BUCKET` — required (results uploaded to `gs://<bucket>/runs/<timestamp>/`)
- `MONGODB_URI` — optional
- `RISK_THRESHOLD` — default 10
- `MAX_RESULTS` — default 30

---

## Data Layout

```
data/
  results/          # Detector output JSON files
  analysis/         # Analysis reports, validation CSVs, pre-analysis JSON
  models/
    cryptobert-streamjacking/   # Fine-tuned model artifacts
logs/               # Runtime logs
```

---

## API Quota

YouTube Data API v3 default: **10,000 units/day**
- Search: 100 units
- `videos.list` / `channels.list`: 5 units each

The enhanced detector supports multiple API key rotation — set additional keys as `YOUTUBE_API_KEY_2`, `YOUTUBE_API_KEY_3`, etc. (check `.env.template` for exact var names). Can additionally set them in `YOUTUBE_API_KEYS` with comma separation.
