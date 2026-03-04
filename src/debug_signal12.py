"""
debug_signal12.py — Diagnostic script for Signal 12 (CryptoBERT)

Checks all reasons why Signal 12 might show 0 support:
  1. Model directory not found
  2. Import failure (transformers / torch not installed)
  3. Calibration threshold too high
  4. Inference output label names not matching expected values
  5. bert_scam_score distribution in MongoDB (are scores being computed but not crossing threshold?)
  6. signal_analysis.py pattern match verification

Run:
    cd streamjacking-detector
    source venv/bin/activate
    python src/debug_signal12.py
"""

import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

SEP = "=" * 65

# ── 1. Module import ──────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  CHECK 1: Module import")
print(SEP)

try:
    from cryptobert_signal import CryptoBERTSignal
    print("✅ cryptobert_signal imported successfully")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    print("   This is why CRYPTOBERT_AVAILABLE = False in the detector.")
    sys.exit(1)

# ── 2. Model availability ─────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  CHECK 2: Model availability & path")
print(SEP)

sig = CryptoBERTSignal()
info = sig.get_model_info()

print(f"   Model path : {info['model_path']}")
print(f"   Path exists: {os.path.isdir(info['model_path'])}")
print(f"   Available  : {info['available']}")
print(f"   Threshold  : {info['threshold']}")

if not info['available']:
    print("\n❌ Model not available. Checking if model files exist...")
    model_path = info['model_path']
    if os.path.isdir(model_path):
        files = os.listdir(model_path)
        print(f"   Files in dir: {files}")
    else:
        print(f"   ❌ Directory does not exist: {model_path}")
        print("   Run: python src/finetune_cryptobert.py  (or equivalent training script)")
    sys.exit(1)

# ── 3. Calibration threshold ──────────────────────────────────────────────────
print(f"\n{SEP}")
print("  CHECK 3: Calibration threshold")
print(SEP)

cal_path = os.path.join(info['model_path'], "calibration.json")
if os.path.exists(cal_path):
    with open(cal_path) as f:
        cal = json.load(f)
    print(f"   calibration.json contents:")
    for k, v in cal.items():
        print(f"     {k}: {v}")
    threshold = cal.get("optimal_threshold", 0.65)
    if threshold > 0.85:
        print(f"\n⚠️  Threshold is very high ({threshold:.2f}). This may cause 0 triggers.")
        print(f"   Consider lowering to 0.65–0.75 for better recall.")
    else:
        print(f"\n✅ Threshold {threshold:.2f} looks reasonable.")
else:
    print("   No calibration.json found — using default threshold 0.65")

# ── 4. Inference test on known scam text ──────────────────────────────────────
print(f"\n{SEP}")
print("  CHECK 4: Inference on scam / legit test cases")
print(SEP)

test_cases = [
    ("Send 1 ETH get 2 ETH back Elon Musk official giveaway limited time [SEP] "
     "LIVE: Elon Musk Bitcoin Giveaway [SEP] bitcoin giveaway elon crypto", "scam"),
    ("Michael Saylor announces new Bitcoin purchase strategy [SEP] "
     "Saylor Bitcoin treasury update [SEP] bitcoin strategy corporate", "legit"),
    ("Double your crypto guaranteed scan QR code claim bonus [SEP] "
     "FREE CRYPTO GIVEAWAY LIVE [SEP] giveaway free crypto airdrop", "scam"),
    ("CNBC covering cryptocurrency markets [SEP] "
     "Markets: Crypto ETF Approval [SEP] finance news crypto", "legit"),
]

all_correct = True
for text, expected in test_cases:
    score = sig.score_text(text)
    triggered, _ = sig.is_triggered(text)
    predicted = "scam" if triggered else "legit"
    ok = predicted == expected
    all_correct = all_correct and ok
    icon = "✅" if ok else "❌"
    preview = text[:70]
    print(f"\n{icon} Expected={expected:<5} | Predicted={predicted:<5} | Score={score:.4f} | Triggered={triggered}")
    print(f'   "{preview}..."')

if all_correct:
    print("\n✅ CHECK 4 PASSED — Model inference is working correctly.")
else:
    print("\n⚠️  CHECK 4 PARTIAL — Some predictions wrong. Threshold may need adjustment.")

# ── 5. MongoDB: bert_scam_score distribution ──────────────────────────────────
print(f"\n{SEP}")
print("  CHECK 5: bert_scam_score distribution in MongoDB")
print(SEP)

try:
    from pymongo import MongoClient
    client = MongoClient(os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/'))
    db = client['streamjacking']
    coll = db['detection_results_latest']

    total = coll.count_documents({})
    has_score = coll.count_documents({"bert_scam_score": {"$exists": True}})
    score_gt0 = coll.count_documents({"bert_scam_score": {"$gt": 0}})
    score_gt_thresh = coll.count_documents({"bert_scam_score": {"$gte": sig.threshold}})

    print(f"   Total documents          : {total}")
    print(f"   Has bert_scam_score field: {has_score}")
    print(f"   bert_scam_score > 0      : {score_gt0}")
    print(f"   bert_scam_score >= {sig.threshold:.2f}   : {score_gt_thresh}  ← these are actual Signal 12 hits")

    if has_score == 0:
        print("\n❌ No documents have bert_scam_score — model was not running during detection.")
        print("   This confirms CRYPTOBERT_AVAILABLE = False at import time during detection runs.")
    elif score_gt0 == 0:
        print("\n⚠️  Scores exist but are all 0 — model loaded but always returned 0.")
        print("   Check label names (CHECK 4 above).")
    elif score_gt_thresh == 0:
        print(f"\n⚠️  Scores > 0 exist ({score_gt0} docs) but none reach threshold {sig.threshold:.2f}.")
        print("   Consider lowering the threshold in calibration.json.")
        # Show the score distribution
        pipeline = [
            {"$match": {"bert_scam_score": {"$gt": 0}}},
            {"$group": {
                "_id": None,
                "max": {"$max": "$bert_scam_score"},
                "avg": {"$avg": "$bert_scam_score"},
                "count": {"$sum": 1}
            }}
        ]
        for doc in coll.aggregate(pipeline):
            print(f"   Score stats: max={doc['max']:.4f}, avg={doc['avg']:.4f}, count={doc['count']}")
            suggested = round(doc['max'] * 0.85, 2)
            print(f"   Suggested threshold: {suggested} (85% of max observed score)")
    else:
        print(f"\n✅ {score_gt_thresh} documents have scores above threshold — Signal 12 IS firing.")
        print("   The 0 support in signal_analysis.py is a pattern-matching issue (CHECK 6).")

    client.close()
except Exception as e:
    print(f"❌ MongoDB check failed: {e}")

# ── 6. signal_analysis.py pattern match ───────────────────────────────────────
print(f"\n{SEP}")
print("  CHECK 6: signal_analysis.py pattern matching")
print(SEP)

import re
patterns = [r"cryptobert", r"semantic scam score"]
sample_signal = f"CryptoBERT semantic scam score: 0.82 (threshold: 0.65)"
for p in patterns:
    matched = bool(re.search(p, sample_signal, re.IGNORECASE))
    print(f"   Pattern '{p}' matches expected string: {'✅' if matched else '❌'}")

print(f"\n   Sample signal string: \"{sample_signal}\"")
print("   If both patterns match ✅, signal_analysis.py will detect Signal 12")
print("   when this string appears in video_signals in MongoDB.")

print(f"\n{SEP}")
print("  SUMMARY")
print(SEP)
print("  Root cause is most likely one of:")
print("  1. Model not found at path → CRYPTOBERT_AVAILABLE=False → never runs")
print("  2. Threshold too high → runs but never triggers")
print("  3. Scores in DB are all 0 → label name mismatch in inference")
print(SEP + "\n")
