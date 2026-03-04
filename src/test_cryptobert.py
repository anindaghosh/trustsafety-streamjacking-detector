"""
Quick test of the fine-tuned CryptoBERT Signal 12.

Loads N records from the eval CSV (which the model has NOT seen during training)
and prints predictions vs. ground truth.

Usage:
    # Default: 10 records from eval CSV
    python src/test_cryptobert.py

    # More records
    python src/test_cryptobert.py --n 30

    # All eval records
    python src/test_cryptobert.py --n 0

    # Test with custom text from stdin
    python src/test_cryptobert.py --text "send ETH get double back Elon Musk giveaway"
"""

import os
import sys
import csv
import argparse

_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_SRC_DIR)
sys.path.insert(0, _SRC_DIR)

EVAL_CSV = os.path.join(PROJECT_ROOT, "data", "training", "cryptobert_eval.csv")

from cryptobert_signal import CryptoBERTSignal


def test_from_csv(n: int):
    if not os.path.exists(EVAL_CSV):
        print(f"❌ Eval CSV not found: {EVAL_CSV}")
        print("   Run export_training_data.py first.")
        return

    with open(EVAL_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("❌ Eval CSV is empty.")
        return

    sample = rows if n == 0 else rows[:n]
    print(f"\n📂 Eval CSV: {EVAL_CSV}")
    print(f"📊 Total eval records: {len(rows)}  |  Testing: {len(sample)}\n")

    sig = CryptoBERTSignal()
    if not sig.is_available():
        print("❌ Model not found. Run finetune_cryptobert.py first.")
        return

    print(f"🎯 Decision threshold: {sig.threshold:.2f}\n")
    print(f"{'#':<4} {'Actual':<8} {'Pred':<8} {'Score':>6}  {'Match':<5}  Text preview")
    print("-" * 90)

    tp = fp = tn = fn = 0
    for i, row in enumerate(sample):
        actual_label = int(row["label"])
        actual_name  = row.get("label_name") or ("scam" if actual_label else "legit")
        text         = row["text"]

        triggered, score = sig.is_triggered(text)
        pred_name = "scam" if triggered else "legit"
        correct   = triggered == bool(actual_label)

        match_sym = "✅" if correct else "❌"
        preview   = text[:65].replace("\n", " ")

        print(f"{i+1:<4} {actual_name:<8} {pred_name:<8} {score:>6.3f}  {match_sym}     {preview}...")

        if triggered and actual_label:     tp += 1
        elif triggered and not actual_label: fp += 1
        elif not triggered and actual_label: fn += 1
        else:                               tn += 1

    total  = tp + fp + tn + fn
    acc    = (tp + tn) / total if total else 0
    prec   = tp / (tp + fp) if (tp + fp) else 0
    rec    = tp / (tp + fn) if (tp + fn) else 0
    f1     = 2 * prec * rec / (prec + rec) if (prec + rec) else 0

    print("\n" + "─" * 90)
    print(f"📊 Results on {total} records:")
    print(f"   Accuracy:  {acc:.1%}   ({tp+tn}/{total} correct)")
    print(f"   Precision: {prec:.1%}")
    print(f"   Recall:    {rec:.1%}")
    print(f"   F1:        {f1:.3f}")
    print(f"\n   Confusion:  TP={tp}  FP={fp}  FN={fn}  TN={tn}")

    if total < 20:
        print("\n⚠️  NOTE: Very small test set — metrics have high variance.")
        print("   Perfect scores likely reflect memorization, not generalization.")
        print("   Run the detector on fresh YouTube data to get a real-world measure.")


def test_custom_text(text: str):
    sig = CryptoBERTSignal()
    if not sig.is_available():
        print("❌ Model not found. Run finetune_cryptobert.py first.")
        return

    triggered, score = sig.is_triggered(text)
    print(f"\n🤖 CryptoBERT Signal 12")
    print(f"   Text:      \"{text[:100]}{'...' if len(text) > 100 else ''}\"")
    print(f"   Score:     {score:.4f}")
    print(f"   Threshold: {sig.threshold:.2f}")
    print(f"   Verdict:   {'🔴 SCAM' if triggered else '🟢 LEGIT'}")


def main():
    parser = argparse.ArgumentParser(description="Test fine-tuned CryptoBERT Signal 12")
    parser.add_argument("--n", type=int, default=10,
                        help="Number of eval records to test (0 = all, default: 10)")
    parser.add_argument("--text", type=str, default=None,
                        help="Score a single custom text string instead of the eval CSV")
    args = parser.parse_args()

    if args.text:
        test_custom_text(args.text)
    else:
        test_from_csv(args.n)


if __name__ == "__main__":
    main()
