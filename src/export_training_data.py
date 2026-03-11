"""
Export Training Data for CryptoBERT Fine-Tuning
================================================
Pulls validated detections from MongoDB and exports a balanced training CSV
suitable for fine-tuning ElKulako/cryptobert as a binary scam classifier.

Label mapping:
    true_positive  → 1 (scam)
    false_negative → 1 (scam)   ← detector missed it, but it IS a scam
    false_positive → 0 (legit)
    true_negative  → 0 (legit)
    uncertain      → excluded

Text format (fed to CryptoBERT):
    {channel_description[:300]} [SEP] {video_title} [SEP] {tags[:10]}

Usage:
    python export_training_data.py
    python export_training_data.py --collection detection_results_latest \\
        --output ../data/training/cryptobert_train.csv --min-text-len 20

Paths default to data/ inside the project root (streamjacking-detector/),
whatever directory the script is invoked from.
"""

import os
import re
import json
import argparse
import random
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import csv

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    print("❌ pymongo not installed. Run: pip install pymongo")
    exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Project root is one level above src/ — works regardless of invocation directory
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_SRC_DIR)

_DEFAULT_TRAIN = os.path.join(PROJECT_ROOT, "data", "training", "cryptobert_train.csv")
_DEFAULT_EVAL  = os.path.join(PROJECT_ROOT, "data", "training", "cryptobert_eval.csv")


# ---------------------------------------------------------------------------
# Label Mapping
# ---------------------------------------------------------------------------

SCAM_LABELS = {"true_positive", "false_negative"}
LEGIT_LABELS = {"false_positive", "true_negative"}
EXCLUDED_LABELS = {"uncertain", "skipped"}

LABEL_TO_INT = {
    "true_positive": 1,
    "false_negative": 1,
    "false_positive": 0,
    "true_negative": 0,
}


# ---------------------------------------------------------------------------
# Text Construction
# ---------------------------------------------------------------------------

def build_text(doc: Dict, max_desc_chars: int = 400) -> str:
    """
    Construct the input text for CryptoBERT from a detection document.

    Priority for description:
      1. video_description  — contains wallet addresses, doubling promises, etc.
      2. channel_description — about-page, may hint at content pivot
      3. channel_title fallback — if no description stored (legacy docs)

    Format matches inference input in analyze_video_enhanced:
        {desc[:400]} [SEP] {video_title} [SEP] {tags[:10]}
    """
    # Prefer video_description (richest scam signal), then channel_description
    video_desc = (doc.get("video_description") or "").strip()
    channel_desc = (doc.get("channel_description") or "").strip()
    desc = video_desc or channel_desc or (doc.get("channel_title") or "").strip()

    video_title = (doc.get("video_title") or "").strip()
    tags = doc.get("tags") or []

    # Truncate description so we don't blow past BERT's 512-token limit
    if len(desc) > max_desc_chars:
        desc = desc[:max_desc_chars].rsplit(" ", 1)[0]

    tag_str = " ".join(str(t) for t in tags[:10]) if tags else ""

    parts = [p for p in [desc, video_title, tag_str] if p]
    return " [SEP] ".join(parts)


def clean_text(text: str) -> str:
    """Basic text cleaning — normalize whitespace, strip control chars."""
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ---------------------------------------------------------------------------
# MongoDB Loader
# ---------------------------------------------------------------------------

def load_validated_docs(collection_name: str) -> List[Dict]:
    """
    Load all documents from MongoDB that have a validation label set.
    Excludes 'uncertain' and 'skipped' labels.
    """
    conn_str = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/")
    try:
        client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
    except ConnectionFailure as e:
        print(f"❌ MongoDB connection failed: {e}")
        print("   Make sure MongoDB is running and MONGODB_URI is set in .env")
        return []

    db = client["streamjacking"]
    collection = db[collection_name]

    docs = list(collection.find(
        {
            "validation.label": {
                "$exists": True,
                "$nin": list(EXCLUDED_LABELS) + [None, ""]
            }
        },
        {
            "video_id": 1,
            "channel_id": 1,
            "video_title": 1,
            "channel_title": 1,
            "channel_description": 1,
            "tags": 1,
            "validation": 1,
            "risk_category": 1,
        }
    ))

    client.close()
    print(f"✅ Loaded {len(docs)} validated documents from '{collection_name}'")
    return docs


# ---------------------------------------------------------------------------
# Export Logic
# ---------------------------------------------------------------------------

def process_docs(
    docs: List[Dict],
    min_text_len: int = 10,
) -> Tuple[List[Dict], Dict]:
    """
    Convert raw MongoDB docs to training rows.

    Returns:
        rows: list of dicts with keys: video_id, channel_id, text, label, label_name, scam_type
        stats: summary statistics dict
    """
    rows = []
    stats = {
        "total_docs": len(docs),
        "included": 0,
        "excluded_unknown_label": 0,
        "excluded_short_text": 0,
        "label_counts": {"scam": 0, "legit": 0},
        "scam_type_counts": {},
    }

    for doc in docs:
        validation = doc.get("validation", {})
        raw_label = validation.get("label", "")

        if raw_label not in LABEL_TO_INT:
            stats["excluded_unknown_label"] += 1
            continue

        binary_label = LABEL_TO_INT[raw_label]

        # Build and clean text
        text = clean_text(build_text(doc))
        if len(text) < min_text_len:
            stats["excluded_short_text"] += 1
            continue

        scam_type = validation.get("scam_type", "") or ""

        rows.append({
            "video_id": doc.get("video_id", ""),
            "channel_id": doc.get("channel_id", ""),
            "text": text,
            "label": binary_label,
            "label_name": "scam" if binary_label == 1 else "legit",
            "raw_label": raw_label,
            "scam_type": scam_type,
        })

        label_name = "scam" if binary_label == 1 else "legit"
        stats["label_counts"][label_name] += 1
        if scam_type:
            stats["scam_type_counts"][scam_type] = (
                stats["scam_type_counts"].get(scam_type, 0) + 1
            )
        stats["included"] += 1

    return rows, stats


def stratified_split(
    rows: List[Dict],
    train_ratio: float = 0.8,
    seed: int = 42,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Stratified 80/20 split that preserves class balance.
    Works even with very small datasets by doing per-class splitting.
    """
    random.seed(seed)

    scam_rows = [r for r in rows if r["label"] == 1]
    legit_rows = [r for r in rows if r["label"] == 0]

    random.shuffle(scam_rows)
    random.shuffle(legit_rows)

    def split_class(items):
        n_train = max(1, int(len(items) * train_ratio))
        return items[:n_train], items[n_train:]

    scam_train, scam_eval = split_class(scam_rows)
    legit_train, legit_eval = split_class(legit_rows)

    train = scam_train + legit_train
    eval_ = scam_eval + legit_eval

    random.shuffle(train)
    random.shuffle(eval_)

    return train, eval_


def write_csv(rows: List[Dict], output_path: str):
    """Write training rows to CSV."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fieldnames = ["video_id", "channel_id", "text", "label", "label_name", "raw_label", "scam_type"]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"   💾 Saved {len(rows)} rows → {output_path}")


def print_stats(stats: Dict, train: List[Dict], eval_: List[Dict]):
    """Print a human-readable data summary."""
    print("\n" + "=" * 60)
    print("  TRAINING DATA SUMMARY")
    print("=" * 60)
    print(f"\n📦 Total docs loaded:        {stats['total_docs']}")
    print(f"✅ Included in dataset:       {stats['included']}")
    print(f"⚠️  Excluded (unknown label):  {stats['excluded_unknown_label']}")
    print(f"⚠️  Excluded (text too short): {stats['excluded_short_text']}")
    print(f"\n🏷️  Label distribution:")
    print(f"   Scam (1):   {stats['label_counts']['scam']}")
    print(f"   Legit (0):  {stats['label_counts']['legit']}")

    total = stats["label_counts"]["scam"] + stats["label_counts"]["legit"]
    if total > 0:
        imbalance = max(
            stats["label_counts"]["scam"],
            stats["label_counts"]["legit"]
        ) / total
        print(f"   Imbalance:  {imbalance:.1%} majority class")
        if imbalance > 0.80:
            print("   ⚠️  WARNING: Heavy class imbalance detected.")
            print("       Consider --augment flag or weighted loss in fine-tuning.")

    if stats["scam_type_counts"]:
        print(f"\n🎯 Scam types:")
        for stype, count in sorted(stats["scam_type_counts"].items(),
                                   key=lambda x: -x[1]):
            print(f"   {stype:<25} {count}")

    print(f"\n📊 Split:")
    train_scam = sum(1 for r in train if r["label"] == 1)
    train_legit = sum(1 for r in train if r["label"] == 0)
    eval_scam = sum(1 for r in eval_ if r["label"] == 1)
    eval_legit = sum(1 for r in eval_ if r["label"] == 0)

    print(f"   Train: {len(train):3d} total  (scam={train_scam}, legit={train_legit})")
    print(f"   Eval:  {len(eval_):3d} total  (scam={eval_scam},  legit={eval_legit})")

    if total < 100:
        print(f"\n⚠️  SMALL DATASET WARNING: Only {total} labeled examples.")
        print("   Fine-tuning may yield noisy results. Consider:")
        print("   1. Label more examples with interactive_validator.py")
        print("   2. Using zero-shot CryptoBERT (no fine-tuning) as a stopgap")
    elif total < 300:
        print(f"\n💡 {total} examples — fine-tuning is feasible but expect ~±5% F1 variance.")
    else:
        print(f"\n✅ {total} examples — good dataset size for reliable fine-tuning.")

    print("=" * 60)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Export validated MongoDB docs as CryptoBERT training data"
    )
    parser.add_argument(
        "--collection",
        default="detection_results_latest",
        help="MongoDB collection name (default: detection_results_latest)",
    )
    parser.add_argument(
        "--output",
        default=_DEFAULT_TRAIN,
        help="Output CSV path (default: data/training/cryptobert_train.csv inside project root)",
    )
    parser.add_argument(
        "--eval-output",
        default=_DEFAULT_EVAL,
        help="Eval split CSV path (default: data/training/cryptobert_eval.csv inside project root)",
    )
    parser.add_argument(
        "--min-text-len",
        type=int,
        default=10,
        help="Minimum text length to include (default: 10 chars)",
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.8,
        help="Fraction of data to use for training (default: 0.8)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--no-split",
        action="store_true",
        help="Export all data to a single file without train/eval split",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("  CRYPTOBERT TRAINING DATA EXPORT")
    print("=" * 60)
    print(f"\n📂 Collection:  {args.collection}")
    print(f"📄 Output:      {args.output}")

    # Load from MongoDB
    docs = load_validated_docs(args.collection)
    if not docs:
        print("❌ No validated documents found. Run interactive_validator.py first.")
        return

    # Process into training rows
    rows, stats = process_docs(docs, min_text_len=args.min_text_len)

    if not rows:
        print("❌ No valid training rows after processing. Check label distribution.")
        return

    if args.no_split:
        write_csv(rows, args.output)
        train, eval_ = rows, []
    else:
        train, eval_ = stratified_split(rows, args.train_ratio, args.seed)
        write_csv(train, args.output)
        write_csv(eval_, args.eval_output)

    print_stats(stats, train, eval_)

    # Save metadata JSON for reference during fine-tuning
    meta_path = args.output.replace(".csv", "_meta.json")
    meta = {
        "exported_at": datetime.now().isoformat(),
        "collection": args.collection,
        "stats": stats,
        "train_count": len(train),
        "eval_count": len(eval_),
        "train_ratio": args.train_ratio,
        "seed": args.seed,
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"\n📋 Metadata saved → {meta_path}")
    print("\n✅ Export complete! Next step: python finetune_cryptobert.py")


if __name__ == "__main__":
    main()
