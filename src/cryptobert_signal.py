"""
CryptoBERT Signal 12 — Semantic Scam Scoring
=============================================
Lazy-loading inference wrapper around the fine-tuned CryptoBERT model.
Used as Signal 12 in EnhancedStreamJackingDetector.

The model is loaded on the first call to score_text() and cached for
subsequent calls, so the ~440MB model does not slow startup time.

Usage from detector code:
    from cryptobert_signal import CryptoBERTSignal

    sig = CryptoBERTSignal()                     # No I/O at this point
    if sig.is_available():
        score = sig.score_text("send ETH giveaway elon musk official")
        # → 0.91  (high scam probability)

Design decisions:
    - Graceful degradation: if model not found, is_available() returns False
      and the detector simply skips Signal 12 (no exception, no crash).
    - Threshold: loaded from calibration.json (optimal_threshold) if present,
      falling back to 0.65 as a conservative default.
    - Thread safety: the model is loaded once and the pipeline is stateless,
      so concurrent calls are safe.
"""

import os
import json
import threading
from typing import Optional, Tuple

# Default model location (relative to src/) — can be overridden in constructor
DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "data",
    "models",
    "cryptobert-streamjacking",
)

DEFAULT_THRESHOLD = 0.65   # Conservative: prefer fewer false positives
MAX_INPUT_CHARS = 1500     # ~512 tokens — truncate input text before tokenization


class CryptoBERTSignal:
    """
    Signal 12: CryptoBERT-based semantic scam scoring.

    Wraps the fine-tuned model with lazy loading and graceful degradation.
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the signal module.

        Args:
            model_path: Path to the saved fine-tuned model directory.
                        Defaults to data/models/cryptobert-streamjacking/.
        """
        self.model_path = os.path.abspath(model_path or DEFAULT_MODEL_PATH)
        self._pipeline = None
        self._threshold: float = DEFAULT_THRESHOLD
        self._load_error: Optional[str] = None
        self._lock = threading.Lock()

        # Try to load threshold from calibration.json (if model exists)
        self._load_threshold()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Return True if the fine-tuned model is present and loadable.

        When False, the detector skips Signal 12 silently.
        """
        return os.path.isdir(self.model_path) and self._load_error is None

    def score_text(self, text: str) -> float:
        """
        Score a text string as scam vs. legitimate.

        Args:
            text: Concatenated channel description + video title + tags.
                  Typically built as:
                      f"{channel_desc[:300]} [SEP] {video_title} [SEP] {tag_str}"

        Returns:
            Scam probability in [0.0, 1.0].
            Returns 0.0 if the model is unavailable.
        """
        if not self.is_available():
            return 0.0

        pipeline = self._get_pipeline()
        if pipeline is None:
            return 0.0

        # Truncate to avoid tokenizer slowdowns on very long texts
        text = text[:MAX_INPUT_CHARS].strip()
        if not text:
            return 0.0

        try:
            result = pipeline(text, truncation=True, max_length=512)
            # transformers 5.x wraps single-input results in an extra list:
            #   4.x: [{"label": "scam", "score": 0.9}, ...]
            #   5.x: [[{"label": "scam", "score": 0.9}, ...]]
            # Unwrap one layer if the first element is itself a list.
            items = result[0] if result and isinstance(result[0], list) else result

            for item in items:
                if item["label"].lower() in ("scam", "label_1", "1"):
                    return round(float(item["score"]), 4)
            # Fallback: if label names differ, derive from legit score
            for item in items:
                if item["label"].lower() in ("legit", "label_0", "0"):
                    return round(1.0 - float(item["score"]), 4)
            return 0.0
        except Exception as e:
            print(f"⚠️  CryptoBERT inference error: {e}")
            return 0.0

    def is_triggered(self, text: str) -> Tuple[bool, float]:
        """
        Convenience method: score text and apply the decision threshold.

        Returns:
            (triggered, score) — triggered is True if score >= threshold.
        """
        score = self.score_text(text)
        return score >= self._threshold, score

    @property
    def threshold(self) -> float:
        """The decision threshold for triggering Signal 12."""
        return self._threshold

    def get_model_info(self) -> dict:
        """Return metadata about the loaded model for logging/debugging."""
        cal_path = os.path.join(self.model_path, "calibration.json")
        cal = {}
        if os.path.exists(cal_path):
            try:
                with open(cal_path) as f:
                    cal = json.load(f)
            except Exception:
                pass

        results_path = os.path.join(self.model_path, "training_results.json")
        results = {}
        if os.path.exists(results_path):
            try:
                with open(results_path) as f:
                    results = json.load(f)
            except Exception:
                pass

        return {
            "model_path": self.model_path,
            "available": self.is_available(),
            "threshold": self._threshold,
            "calibration": cal,
            "training_results": results.get("eval_metrics", {}),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_threshold(self):
        """Read the calibration threshold from calibration.json if present."""
        cal_path = os.path.join(self.model_path, "calibration.json")
        if os.path.exists(cal_path):
            try:
                with open(cal_path) as f:
                    cal = json.load(f)
                self._threshold = float(
                    cal.get("optimal_threshold", DEFAULT_THRESHOLD)
                )
            except Exception:
                self._threshold = DEFAULT_THRESHOLD

    def _get_pipeline(self):
        """
        Lazy-load the HuggingFace pipeline on first call. Thread-safe.
        """
        if self._pipeline is not None:
            return self._pipeline

        with self._lock:
            # Double-checked locking
            if self._pipeline is not None:
                return self._pipeline

            try:
                from transformers import pipeline as hf_pipeline
                import torch

                # Resolve device: CUDA (int 0) > MPS (string "mps") > CPU (int -1)
                # HuggingFace pipeline accepts both int and string device args
                if torch.cuda.is_available():
                    device = 0          # CUDA device 0
                elif torch.backends.mps.is_available():
                    device = "mps"      # Apple Silicon GPU
                else:
                    device = -1         # CPU

                device_label = {0: "CUDA", "mps": "Apple Silicon MPS", -1: "CPU"}[device]
                print(f"🤖 Loading CryptoBERT Signal 12 on {device_label}...")

                self._pipeline = hf_pipeline(
                    "text-classification",
                    model=self.model_path,
                    tokenizer=self.model_path,
                    device=device,
                    top_k=None,          # Return scores for all labels
                    function_to_apply="softmax",
                )
                print("✅ CryptoBERT Signal 12 loaded successfully")
            except ImportError:
                self._load_error = "transformers not installed"
                print("⚠️  Signal 12 unavailable: transformers not installed")
                print("   Install with: pip install transformers torch")
            except Exception as e:
                self._load_error = str(e)
                print(f"⚠️  Signal 12 failed to load: {e}")

        return self._pipeline


# ---------------------------------------------------------------------------
# CLI — quick test / sanity check
# ---------------------------------------------------------------------------

def _run_test(model_path: Optional[str] = None):
    """Quick sanity test for the signal module."""
    sig = CryptoBERTSignal(model_path=model_path)

    print("\n" + "=" * 60)
    print("  CRYPTOBERT SIGNAL 12 — SANITY TEST")
    print("=" * 60)

    info = sig.get_model_info()
    print(f"\n📂 Model path: {info['model_path']}")
    print(f"✅ Available:  {info['available']}")
    print(f"🎯 Threshold:  {info['threshold']}")

    if not sig.is_available():
        print("\n❌ Model not found. Run finetune_cryptobert.py first.")
        return

    if info["training_results"]:
        metrics = info["training_results"]
        print(f"\n📊 Training metrics:")
        for k, v in metrics.items():
            print(f"   {k}: {v}")

    test_cases = [
        # (text, expected_label)
        (
            "Send 1 ETH get 2 ETH back Elon Musk official giveaway limited time only [SEP] "
            "LIVE: Elon Musk Bitcoin Giveaway Event [SEP] bitcoin giveaway elon crypto",
            "scam",
        ),
        (
            "Bitcoin price analysis and technical indicators weekly update market report [SEP] "
            "BTC Weekly TA — Key Support Levels to Watch [SEP] bitcoin analysis trading",
            "legit",
        ),
        (
            "Double your crypto guaranteed scan QR code claim bonus [SEP] "
            "FREE CRYPTO GIVEAWAY LIVE [SEP] giveaway free crypto airdrop",
            "scam",
        ),
        (
            "CNBC Fast Money covering cryptocurrency markets and blockchain technology [SEP] "
            "Markets Discussion: Crypto ETF Approval Impact [SEP] finance news crypto",
            "legit",
        ),
    ]

    print("\n🧪 Test cases:")
    print("-" * 60)
    correct = 0
    for text, expected in test_cases:
        score = sig.score_text(text)
        triggered, _ = sig.is_triggered(text)
        predicted = "scam" if triggered else "legit"
        match = "✅" if predicted == expected else "❌"
        correct += 1 if predicted == expected else 0
        label_preview = text[:60].replace("\n", " ")
        print(f"\n{match} Expected: {expected:<6} | Score: {score:.3f} | Triggered: {triggered}")
        print(f"   \"{label_preview}...\"")

    print(f"\n📈 Accuracy on test cases: {correct}/{len(test_cases)}")
    print("=" * 60)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Test CryptoBERT Signal 12")
    parser.add_argument("--model-path", default=None,
                        help="Path to fine-tuned model (default: data/models/cryptobert-streamjacking)")
    args = parser.parse_args()
    _run_test(model_path=args.model_path)
