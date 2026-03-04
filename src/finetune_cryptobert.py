"""
Fine-Tune CryptoBERT for Streamjacking Detection
=================================================
Fine-tunes ElKulako/cryptobert as a binary scam classifier
(scam=1 / legit=0) on the labeled streamjacking dataset.

The fine-tuned model is saved locally and used as Signal 12
in the streamjacking detector via cryptobert_signal.py.

Usage:
    # CPU (works everywhere, slowest)
    python finetune_cryptobert.py

    # Apple Silicon Mac (M1/M2/M3/M4) — uses MPS GPU automatically
    python finetune_cryptobert.py --batch-size 16

    # NVIDIA GPU / Colab T4
    python finetune_cryptobert.py --batch-size 16 --epochs 5

    # Custom paths
    python finetune_cryptobert.py \\
        --train ../data/training/cryptobert_train.csv \\
        --eval  ../data/training/cryptobert_eval.csv \\
        --output ../data/models/cryptobert-streamjacking \\
        --epochs 3 --batch-size 8

Outputs:
    data/models/cryptobert-streamjacking/     ← HuggingFace model + tokenizer
    data/models/cryptobert-streamjacking/calibration.json ← threshold config
    data/models/cryptobert-streamjacking/training_results.json ← F1, loss, etc.
"""

import os
import json
import argparse
import csv
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Project root is one level above src/
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_SRC_DIR)

# Default paths — always inside the project root
_DEFAULT_TRAIN  = os.path.join(PROJECT_ROOT, "data", "training", "cryptobert_train.csv")
_DEFAULT_EVAL   = os.path.join(PROJECT_ROOT, "data", "training", "cryptobert_eval.csv")
_DEFAULT_OUTPUT = os.path.join(PROJECT_ROOT, "data", "models", "cryptobert-streamjacking")

# ---------------------------------------------------------------------------
# Dependency checks — provide clear error messages for each missing package
# ---------------------------------------------------------------------------

def _check_deps():
    missing = []
    try:
        import torch
    except ImportError:
        missing.append("torch")
    try:
        import transformers
    except ImportError:
        missing.append("transformers")
    try:
        import datasets
    except ImportError:
        missing.append("datasets")
    try:
        import sklearn
    except ImportError:
        missing.append("scikit-learn")
    try:
        import accelerate
    except ImportError:
        missing.append("accelerate")

    if missing:
        print(f"❌ Missing dependencies: {', '.join(missing)}")
        print(f"   Install with: pip install {' '.join(missing)}")
        print("   Or: pip install -r requirements.txt")
        exit(1)

_check_deps()

import torch
import numpy as np
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback,
)
from datasets import Dataset
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    confusion_matrix,
)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_MODEL = "ElKulako/cryptobert"
MAX_LENGTH = 512
LABEL_NAMES = ["legit", "scam"]
SCAM_SCORE_THRESHOLD = 0.65   # Default; also saved to calibration.json


# ---------------------------------------------------------------------------
# Data Loading
# ---------------------------------------------------------------------------

def load_csv(path: str) -> List[Dict]:
    """Load a CSV exported by export_training_data.py"""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Training data not found: {path}\n"
                                f"Run export_training_data.py first.")
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "text": row["text"],
                "label": int(row["label"]),
            })
    return rows


def rows_to_hf_dataset(rows: List[Dict], tokenizer) -> Dataset:
    """Tokenize rows and return a HuggingFace Dataset."""
    texts = [r["text"] for r in rows]
    labels = [r["label"] for r in rows]

    encodings = tokenizer(
        texts,
        truncation=True,
        padding="max_length",
        max_length=MAX_LENGTH,
        return_tensors=None,      # Return plain lists for Dataset
    )

    dataset = Dataset.from_dict({
        "input_ids": encodings["input_ids"],
        "attention_mask": encodings["attention_mask"],
        "label": labels,
    })
    dataset.set_format("torch")
    return dataset


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(eval_pred) -> Dict:
    """Called by HuggingFace Trainer after each eval epoch."""
    logits, labels = eval_pred
    probs = torch.softmax(torch.tensor(logits), dim=-1).numpy()
    scam_probs = probs[:, 1]
    preds = (scam_probs >= SCAM_SCORE_THRESHOLD).astype(int)

    f1 = f1_score(labels, preds, zero_division=0)
    precision = precision_score(labels, preds, zero_division=0)
    recall = recall_score(labels, preds, zero_division=0)

    # AUC — only meaningful if both classes are present in eval
    try:
        auc = roc_auc_score(labels, scam_probs)
    except ValueError:
        auc = 0.0

    return {
        "f1": round(f1, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "auc": round(auc, 4),
    }


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------

def compute_calibration(
    trainer: Trainer,
    eval_dataset: Dataset,
    true_labels: List[int],
) -> Dict:
    """
    Compute a simple threshold scan over the eval set to determine
    the F1-optimal decision threshold. Saves this as calibration.json
    so the inference module (cryptobert_signal.py) uses the same threshold.
    """
    print("\n🔧 Computing calibration threshold...")
    predictions = trainer.predict(eval_dataset)
    logits = predictions.predictions
    probs = torch.softmax(torch.tensor(logits), dim=-1).numpy()
    scam_probs = probs[:, 1]

    best_threshold = 0.5
    best_f1 = 0.0

    for threshold in np.arange(0.3, 0.95, 0.05):
        preds = (scam_probs >= threshold).astype(int)
        f1 = f1_score(true_labels, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = round(float(threshold), 2)

    print(f"   ✅ Optimal threshold: {best_threshold:.2f} (F1={best_f1:.4f})")
    return {
        "optimal_threshold": best_threshold,
        "threshold_f1": round(best_f1, 4),
        "default_threshold": SCAM_SCORE_THRESHOLD,
        "calibrated_at": datetime.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def fine_tune(
    train_rows: List[Dict],
    eval_rows: List[Dict],
    output_dir: str,
    epochs: int = 3,
    batch_size: int = 8,
    learning_rate: float = 2e-5,
    freeze_layers: int = 8,
    label_smoothing: float = 0.1,
    seed: int = 42,
) -> Dict:
    """
    Fine-tune CryptoBERT for binary scam classification.

    Args:
        freeze_layers: Number of bottom BERT encoder layers to freeze (0-12).
                       Freezing reduces trainable params and helps generalization
                       on small datasets. Default 8 (freeze lower 2/3, train top 1/3).
        label_smoothing: Smoothing factor for target labels (0 = hard labels,
                         0.1 = soften 0→0.1 / 1→0.9). Reduces overconfidence.

    Returns a dict of training results / metrics.
    """
    # Detect best available device: CUDA > MPS (Apple Silicon) > CPU
    if torch.cuda.is_available():
        device = "cuda"
    elif torch.backends.mps.is_available():
        device = "mps"
    else:
        device = "cpu"

    print(f"\n🖥️  Device: {device.upper()}")
    if device == "mps":
        print("   🍎 Apple Silicon GPU detected — using MPS backend")
    elif device == "cpu":
        print("   ℹ️  Running on CPU — this may take 20–60 minutes for large datasets.")
        print("   TIP: Run on your Mac GPU automatically (M1/M2/M3/M4 detects MPS).")

    print(f"\n⬇️  Loading base model: {BASE_MODEL}")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=2,
        id2label={0: "legit", 1: "scam"},
        label2id={"legit": 0, "scam": 1},
        ignore_mismatched_sizes=True,
    )

    # ── Layer Freezing ────────────────────────────────────────────────────────
    # Freeze the bottom `freeze_layers` of 12 BERT encoder layers.
    # Only the top layers + classifier head will receive gradient updates.
    # This dramatically reduces effective trainable params on small datasets.
    n_layers = len(model.roberta.encoder.layer)
    freeze_layers = max(0, min(freeze_layers, n_layers - 1))  # keep at least 1 trainable

    if freeze_layers > 0:
        # Freeze embeddings
        for param in model.roberta.embeddings.parameters():
            param.requires_grad = False
        # Freeze bottom N encoder layers
        for i, layer in enumerate(model.roberta.encoder.layer):
            if i < freeze_layers:
                for param in layer.parameters():
                    param.requires_grad = False

        trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
        total     = sum(p.numel() for p in model.parameters())
        print(f"\n� Layer freezing: {freeze_layers}/{n_layers} encoder layers frozen")
        print(f"   Trainable params: {trainable:,} / {total:,} ({100*trainable/total:.1f}%)")
    else:
        print("\n🔓 No layer freezing — all parameters trainable")
    # ─────────────────────────────────────────────────────────────────────────

    print(f"\n�🔤 Tokenizing {len(train_rows)} train / {len(eval_rows)} eval examples...")
    train_dataset = rows_to_hf_dataset(train_rows, tokenizer)
    eval_dataset = rows_to_hf_dataset(eval_rows, tokenizer)

    # Handle class imbalance with weighted loss if ratio > 3:1
    scam_count = sum(1 for r in train_rows if r["label"] == 1)
    legit_count = len(train_rows) - scam_count
    class_ratio = max(scam_count, legit_count) / max(min(scam_count, legit_count), 1)

    if class_ratio > 3.0:
        print(f"\n⚠️  Class imbalance detected ({class_ratio:.1f}:1). Using class weights.")
        # Compute weights inversely proportional to class frequency
        total = len(train_rows)
        weight_for_scam = total / (2 * max(scam_count, 1))
        weight_for_legit = total / (2 * max(legit_count, 1))
        class_weights = torch.tensor(
            [weight_for_legit, weight_for_scam], dtype=torch.float
        ).to(device if device != "mps" else "cpu")  # MPS weights stay on CPU; loss_fn moves them
    else:
        class_weights = None

    os.makedirs(output_dir, exist_ok=True)

    # Warmup steps: ~10% of total training steps (helps LR ramp up smoothly)
    steps_per_epoch = max(1, len(train_rows) // batch_size)
    total_steps = steps_per_epoch * epochs
    warmup_steps = max(1, int(total_steps * 0.10))

    if label_smoothing > 0:
        print(f"\n🎯 Label smoothing: {label_smoothing} (0→{label_smoothing:.2f}, 1→{1-label_smoothing:.2f})")

    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size * 2,
        learning_rate=learning_rate,
        weight_decay=0.01,
        warmup_steps=warmup_steps,
        label_smoothing_factor=label_smoothing,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_steps=10,
        seed=seed,
        report_to="none",
        # Precision: CUDA supports fp16, MPS supports bf16, CPU uses fp32
        fp16=(device == "cuda"),
        bf16=(device == "mps"),
        # pin_memory only works with CUDA DataLoaders
        dataloader_pin_memory=(device == "cuda"),
    )

    # Custom Trainer to support weighted loss for imbalanced datasets
    class WeightedTrainer(Trainer):
        def __init__(self, *args, class_weights=None, **kwargs):
            super().__init__(*args, **kwargs)
            self._class_weights = class_weights

        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            logits = outputs.logits

            if self._class_weights is not None:
                # Move weights to same device as logits at call time.
                # This handles CPU/CUDA/MPS without needing to know the device upfront.
                loss_fn = torch.nn.CrossEntropyLoss(
                    weight=self._class_weights.to(logits.device)
                )
            else:
                loss_fn = torch.nn.CrossEntropyLoss()

            loss = loss_fn(logits, labels)
            return (loss, outputs) if return_outputs else loss

    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
        class_weights=class_weights,
    )

    print(f"\n🚀 Starting fine-tuning ({epochs} epochs, batch_size={batch_size})...")
    trainer.train()

    # Final evaluation
    print("\n📊 Running final evaluation...")
    eval_results = trainer.evaluate()
    print(f"   F1:        {eval_results.get('eval_f1', 'N/A'):.4f}")
    print(f"   Precision: {eval_results.get('eval_precision', 'N/A'):.4f}")
    print(f"   Recall:    {eval_results.get('eval_recall', 'N/A'):.4f}")
    print(f"   AUC:       {eval_results.get('eval_auc', 'N/A'):.4f}")

    # Detailed classification report
    predictions = trainer.predict(eval_dataset)
    logits = predictions.predictions
    probs = torch.softmax(torch.tensor(logits), dim=-1).numpy()
    preds = (probs[:, 1] >= SCAM_SCORE_THRESHOLD).astype(int)
    true_labels = [r["label"] for r in eval_rows]

    print("\n📋 Classification Report (eval set):")
    print(classification_report(true_labels, preds, target_names=LABEL_NAMES))

    cm = confusion_matrix(true_labels, preds)
    print("Confusion Matrix:")
    print(f"   TN={cm[0,0]:3d}  FP={cm[0,1]:3d}")
    print(f"   FN={cm[1,0]:3d}  TP={cm[1,1]:3d}")

    # Save final model and tokenizer
    print(f"\n💾 Saving model to {output_dir}...")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)

    return {
        "trainer": trainer,
        "eval_dataset": eval_dataset,
        "eval_rows": eval_rows,
        "eval_results": eval_results,
    }


# ---------------------------------------------------------------------------
# Calibration & Result Saving
# ---------------------------------------------------------------------------

def save_calibration(
    trainer,
    eval_dataset,
    eval_rows: List[Dict],
    output_dir: str,
):
    """Run calibration and save threshold to JSON."""
    true_labels = [r["label"] for r in eval_rows]
    calibration = compute_calibration(trainer, eval_dataset, true_labels)

    cal_path = os.path.join(output_dir, "calibration.json")
    with open(cal_path, "w") as f:
        json.dump(calibration, f, indent=2)
    print(f"\n📋 Calibration saved → {cal_path}")
    return calibration


def save_training_results(
    train_rows: List[Dict],
    eval_rows: List[Dict],
    eval_results: Dict,
    calibration: Dict,
    output_dir: str,
    args: argparse.Namespace,
):
    """Save a training summary JSON for later reference."""
    results = {
        "trained_at": datetime.now().isoformat(),
        "base_model": BASE_MODEL,
        "output_dir": output_dir,
        "hyperparameters": {
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "learning_rate": args.lr,
            "freeze_layers": args.freeze_layers,
            "label_smoothing": args.label_smoothing,
        },
        "dataset": {
            "train_count": len(train_rows),
            "eval_count": len(eval_rows),
            "train_scam": sum(1 for r in train_rows if r["label"] == 1),
            "eval_scam": sum(1 for r in eval_rows if r["label"] == 1),
        },
        "eval_metrics": {
            k: v for k, v in eval_results.items() if k.startswith("eval_")
        },
        "calibration": calibration,
    }

    results_path = os.path.join(output_dir, "training_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"📊 Training results saved → {results_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Fine-tune CryptoBERT for streamjacking detection (Signal 12)"
    )
    parser.add_argument(
        "--train",
        default=_DEFAULT_TRAIN,
        help="Training CSV from export_training_data.py",
    )
    parser.add_argument(
        "--eval",
        default=_DEFAULT_EVAL,
        help="Eval CSV from export_training_data.py",
    )
    parser.add_argument(
        "--output",
        default=_DEFAULT_OUTPUT,
        help="Directory to save fine-tuned model",
    )
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--freeze-layers",
        type=int,
        default=8,
        help="Number of bottom BERT encoder layers to freeze (0=none, default: 8 of 12)",
    )
    parser.add_argument(
        "--label-smoothing",
        type=float,
        default=0.1,
        help="Label smoothing factor (0=off, default: 0.1)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("  CRYPTOBERT FINE-TUNING FOR STREAMJACKING DETECTION")
    print("=" * 60)
    print(f"\n📂 Train:   {args.train}")
    print(f"📂 Eval:    {args.eval}")
    print(f"📂 Output:  {args.output}")
    print(f"⚙️  Epochs:  {args.epochs}  |  Batch: {args.batch_size}  |  LR: {args.lr}")
    print(f"⚙️  Freeze:  {args.freeze_layers} layers  |  Label smoothing: {args.label_smoothing}")

    # Load data
    try:
        train_rows = load_csv(args.train)
        eval_rows = load_csv(args.eval)
    except FileNotFoundError as e:
        print(f"\n❌ {e}")
        return

    if len(train_rows) < 20:
        print(f"\n⚠️  WARNING: Only {len(train_rows)} training examples.")
        print("   Fine-tuning with so few examples is unlikely to generalize.")
        print("   Label more data with interactive_validator.py first.")
        resp = input("   Continue anyway? [y/N] ").strip().lower()
        if resp != "y":
            return

    # Fine-tune
    result = fine_tune(
        train_rows=train_rows,
        eval_rows=eval_rows,
        output_dir=args.output,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        freeze_layers=args.freeze_layers,
        label_smoothing=args.label_smoothing,
        seed=args.seed,
    )

    # Calibrate and save
    calibration = save_calibration(
        result["trainer"],
        result["eval_dataset"],
        result["eval_rows"],
        args.output,
    )
    save_training_results(
        train_rows,
        eval_rows,
        result["eval_results"],
        calibration,
        args.output,
        args,
    )

    print("\n" + "=" * 60)
    print("✅ Fine-tuning complete!")
    print(f"   Model saved to: {args.output}")
    print("   Next step: the model will be loaded as Signal 12 automatically")
    print("   by cryptobert_signal.py when you run the detector.")
    print("=" * 60)


if __name__ == "__main__":
    main()
