#!/usr/bin/env python3
"""
W.O.P.R. QLoRA Fine-Tuning Pipeline
====================================
Export -> Train -> Merge -> Quantize -> Import to Ollama

Closes the learning loop: Blackboard training data feeds back into
the dolphin-mistral:7b base model via QLoRA on RTX 4070 Max-Q (8GB).

Usage:
    python finetune_wopr.py --export        # Export Blackboard data
    python finetune_wopr.py --train         # QLoRA fine-tuning
    python finetune_wopr.py --merge         # Merge LoRA + quantize
    python finetune_wopr.py --import-model  # Import to Ollama
    python finetune_wopr.py --full          # All stages
    python finetune_wopr.py --status        # Show data stats
"""

import argparse
import glob
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────
PROJECT_DIR = Path(__file__).resolve().parent
TRAINING_DATA_DIR = PROJECT_DIR / "training_data"
LORA_OUTPUT_DIR = PROJECT_DIR / "wopr_lora"
MERGED_OUTPUT_DIR = PROJECT_DIR / "wopr_merged"
MODELFILE_PATH = PROJECT_DIR / "joshua_cybersec.modelfile"
CURATED_DATASET = TRAINING_DATA_DIR / "wopr_cybersec_curated.jsonl"
JOSHUA_VENV = Path("/home/sirrand/.local/share/sounds/joshua/venv")

# ── Model IDs ──────────────────────────────────────────────────────────
HF_MODEL_ID = "cognitivecomputations/dolphin-2.8-mistral-7b-v02"
OLLAMA_BASE_TAG = "joshua:latest"
OLLAMA_FINETUNE_TAG = "joshua:cybersec"

# ── Logging ────────────────────────────────────────────────────────────
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("wopr-finetune")


# ========================================================================
#  Utility helpers
# ========================================================================

def run_cmd(cmd: str, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    logger.debug(f"CMD: {cmd}")
    return subprocess.run(
        cmd, shell=True, capture_output=True, text=True,
        check=check, timeout=timeout,
    )


def count_jsonl_lines(filepath: Path) -> int:
    """Count non-empty lines in a JSONL file."""
    if not filepath.exists():
        return 0
    count = 0
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def get_vram_free_mb() -> float:
    """Return free VRAM in MB via nvidia-smi, or -1 if unavailable."""
    try:
        result = run_cmd(
            "nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits",
            check=True, timeout=10,
        )
        return float(result.stdout.strip().split("\n")[0])
    except Exception:
        return -1.0


def get_vram_total_mb() -> float:
    """Return total VRAM in MB via nvidia-smi, or -1 if unavailable."""
    try:
        result = run_cmd(
            "nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits",
            check=True, timeout=10,
        )
        return float(result.stdout.strip().split("\n")[0])
    except Exception:
        return -1.0


def print_banner(title: str):
    """Print a W.O.P.R.-style stage banner."""
    width = 60
    border = "=" * width
    print(f"\n{border}")
    print(f"  W.O.P.R. FINE-TUNING PIPELINE :: {title}")
    print(f"{border}\n")


def print_separator():
    print("-" * 60)


def check_package_installed(package_name: str) -> bool:
    """Check if a Python package is importable."""
    try:
        __import__(package_name)
        return True
    except ImportError:
        return False


# ========================================================================
#  Stage 1: EXPORT
# ========================================================================

def stage_export():
    """Export training data from Blackboard via TrainingPipeline."""
    print_banner("STAGE 1 — EXPORT")

    # Ensure training_data directory exists
    TRAINING_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Attempt Blackboard export via TrainingPipeline
    try:
        sys.path.insert(0, str(PROJECT_DIR))
        from blackboard import BlackboardClient
        from learning import TrainingPipeline

        bb = BlackboardClient()
        pipeline = TrainingPipeline(bb)
        filepath, count = pipeline.export_training_data()

        if filepath:
            logger.info(f"Blackboard export: {count} examples -> {filepath}")
        else:
            logger.warning(
                f"Blackboard export returned no file (count={count}). "
                "This is normal if Blackboard is offline or below minimum threshold."
            )
    except Exception as e:
        logger.warning(f"Blackboard export failed: {e}")
        logger.info("Continuing with existing training data files.")

    # Tally all training data
    curated_count = count_jsonl_lines(CURATED_DATASET)
    blackboard_count = 0
    blackboard_files = sorted(TRAINING_DATA_DIR.glob("wopr_training_*.jsonl"))

    for bf in blackboard_files:
        blackboard_count += count_jsonl_lines(bf)

    total = curated_count + blackboard_count

    print_separator()
    print(f"  Curated dataset:    {curated_count:>6} examples  ({CURATED_DATASET.name})")
    print(f"  Blackboard exports: {blackboard_count:>6} examples  ({len(blackboard_files)} files)")
    print(f"  {'─' * 40}")
    print(f"  TOTAL:              {total:>6} examples")
    print_separator()

    if total == 0:
        logger.error("No training data found. Cannot proceed to training.")
        logger.info(f"Place curated data at: {CURATED_DATASET}")
        return False

    logger.info(f"Export stage complete. {total} examples ready for training.")
    return True


# ========================================================================
#  Stage 2: TRAIN
# ========================================================================

def stage_train():
    """QLoRA fine-tuning on RTX 4070 Max-Q."""
    print_banner("STAGE 2 — QLORA TRAINING")

    # ── Prerequisite checks ────────────────────────────────────────────
    missing = []
    for pkg, pip_name in [("peft", "peft"), ("trl", "trl")]:
        if not check_package_installed(pkg):
            missing.append((pkg, pip_name))

    if missing:
        logger.error("Missing required packages:")
        for pkg, pip_name in missing:
            print(f"  pip install {pip_name}")
        print()
        logger.error("Install the above packages and retry.")
        return False

    for pkg in ["torch", "transformers", "datasets", "bitsandbytes"]:
        if not check_package_installed(pkg):
            logger.error(f"Required package '{pkg}' is not installed.")
            return False

    import torch
    if not torch.cuda.is_available():
        logger.error("CUDA is not available. QLoRA requires a CUDA GPU.")
        return False

    gpu_name = torch.cuda.get_device_name(0)
    logger.info(f"GPU detected: {gpu_name}")

    # ── VRAM safety check ──────────────────────────────────────────────
    vram_free = get_vram_free_mb()
    vram_total = get_vram_total_mb()
    logger.info(f"VRAM: {vram_free:.0f} MB free / {vram_total:.0f} MB total")

    if 0 < vram_free < 7000:
        logger.warning(
            f"Free VRAM is {vram_free:.0f} MB (< 7000 MB recommended). "
            "Training may OOM. Will attempt to free VRAM by stopping services."
        )

    # ── Free VRAM: stop Ollama and F5-TTS ──────────────────────────────
    print_separator()
    logger.info("Stopping GPU-resident services to free VRAM...")

    # Stop F5-TTS voice server
    try:
        run_cmd("systemctl --user stop joshua-voice", check=False, timeout=15)
        logger.info("F5-TTS voice server stopped.")
    except Exception as e:
        logger.warning(f"Could not stop F5-TTS: {e}")

    # Stop Ollama model
    try:
        run_cmd("ollama stop joshua:latest", check=False, timeout=15)
        logger.info("Ollama joshua:latest unloaded.")
    except Exception as e:
        logger.warning(f"Could not stop Ollama model: {e}")

    logger.info("Waiting 5 seconds for VRAM release...")
    time.sleep(5)

    # Re-check VRAM
    vram_free = get_vram_free_mb()
    logger.info(f"VRAM after cleanup: {vram_free:.0f} MB free")

    if 0 < vram_free < 7000:
        logger.error(
            f"Only {vram_free:.0f} MB VRAM free after stopping services. "
            "Need at least ~7 GB for QLoRA training. "
            "Close other GPU applications and retry."
        )
        return False

    # ── Load training data ─────────────────────────────────────────────
    print_separator()
    logger.info("Loading training data...")

    all_examples = []

    # Load curated dataset
    if CURATED_DATASET.exists():
        with open(CURATED_DATASET, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        all_examples.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Skipping malformed line in curated data: {e}")

    # Load Blackboard exports
    for bf in sorted(TRAINING_DATA_DIR.glob("wopr_training_*.jsonl")):
        with open(bf, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        all_examples.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Skipping malformed line in {bf.name}: {e}")

    if not all_examples:
        logger.error("No training examples loaded. Run --export first.")
        return False

    logger.info(f"Loaded {len(all_examples)} training examples.")

    # ── Format for SFTTrainer ──────────────────────────────────────────
    # SFTTrainer expects a dataset with a text or messages field.
    # Our JSONL uses {"messages": [{"role": ..., "content": ...}, ...]}
    # Validate and normalize the format.

    formatted = []
    for ex in all_examples:
        if "messages" in ex and isinstance(ex["messages"], list):
            # Already in messages format — good
            formatted.append(ex)
        elif "context" in ex and "reasoning" in ex:
            # Raw Blackboard format — needs adaptation
            from config import SYSTEM_PROMPT
            parts = []
            if ex.get("reasoning"):
                parts.append(ex["reasoning"])
            if ex.get("action"):
                parts.append(f"Action: {ex['action']}")
            if ex.get("observation"):
                parts.append(ex["observation"])
            if ex.get("conclusion"):
                parts.append(ex["conclusion"])
            assistant_msg = " ".join(parts)
            if ex.get("context") and assistant_msg:
                formatted.append({
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": ex["context"]},
                        {"role": "assistant", "content": assistant_msg},
                    ]
                })
        else:
            logger.warning(f"Skipping example with unknown format: {list(ex.keys())}")

    if not formatted:
        logger.error("No valid training examples after formatting.")
        return False

    logger.info(f"Formatted {len(formatted)} examples for SFTTrainer.")

    # ── Write formatted dataset to temp file ───────────────────────────
    formatted_path = TRAINING_DATA_DIR / "_formatted_train.jsonl"
    with open(formatted_path, "w", encoding="utf-8") as f:
        for ex in formatted:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    # ── Import training libraries ──────────────────────────────────────
    print_separator()
    logger.info("Initializing model and training components (unsloth)...")

    from unsloth import FastLanguageModel
    from trl import SFTTrainer
    from transformers import TrainingArguments
    from datasets import load_dataset

    # ── Load base model via unsloth (handles 8GB VRAM gracefully) ─────
    logger.info(f"Loading base model via unsloth: {HF_MODEL_ID}")
    logger.info("This may download ~4 GB on first run...")

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=HF_MODEL_ID,
        max_seq_length=2048,
        dtype=None,  # auto-detect
        load_in_4bit=True,
    )

    vram_after_load = get_vram_free_mb()
    logger.info(f"Model loaded. VRAM remaining: {vram_after_load:.0f} MB")

    # ── LoRA via unsloth ──────────────────────────────────────────────
    model = FastLanguageModel.get_peft_model(
        model,
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
    )

    # Print trainable parameter stats
    trainable, total = 0, 0
    for _, param in model.named_parameters():
        total += param.numel()
        if param.requires_grad:
            trainable += param.numel()

    pct = 100 * trainable / total if total > 0 else 0
    logger.info(
        f"Trainable parameters: {trainable:,} / {total:,} ({pct:.2f}%)"
    )

    # ── Load dataset ───────────────────────────────────────────────────
    dataset = load_dataset("json", data_files=str(formatted_path), split="train")
    logger.info(f"Dataset loaded: {len(dataset)} examples")

    # ── Training arguments ─────────────────────────────────────────────
    training_args = TrainingArguments(
        output_dir=str(LORA_OUTPUT_DIR),
        num_train_epochs=3,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        gradient_checkpointing=True,
        optim="paged_adamw_8bit",
        learning_rate=2e-4,
        warmup_steps=20,
        logging_steps=10,
        save_steps=50,
        save_total_limit=3,
        bf16=True,
        report_to="none",
        remove_unused_columns=False,
        dataloader_pin_memory=False,
        lr_scheduler_type="cosine",
        weight_decay=0.01,
        max_grad_norm=0.3,
    )

    # ── Formatting function for chat messages ──────────────────────────
    def formatting_func(example):
        """Convert messages list to ChatML-formatted text for SFTTrainer."""
        output_texts = []
        messages = example.get("messages", [])
        # Handle batched input (list of lists) vs single input
        if messages and isinstance(messages[0], list):
            # Batched
            for msg_list in messages:
                text = _format_messages(msg_list)
                output_texts.append(text)
        else:
            # Single example
            text = _format_messages(messages)
            output_texts.append(text)
        return output_texts

    def _format_messages(messages):
        """Format a single list of message dicts into ChatML string."""
        text = ""
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                text += f"<|im_start|>system\n{content}<|im_end|>\n"
            elif role == "user":
                text += f"<|im_start|>user\n{content}<|im_end|>\n"
            elif role == "assistant":
                text += f"<|im_start|>assistant\n{content}<|im_end|>\n"
        return text

    # ── Initialize trainer ─────────────────────────────────────────────
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        tokenizer=tokenizer,
        formatting_func=formatting_func,
        max_seq_length=2048,
    )

    # ── Train ──────────────────────────────────────────────────────────
    print_separator()
    logger.info("INITIATING TRAINING SEQUENCE...")
    logger.info(f"  Epochs: {training_args.num_train_epochs}")
    logger.info(f"  Batch size: {training_args.per_device_train_batch_size}")
    logger.info(f"  Gradient accumulation: {training_args.gradient_accumulation_steps}")
    logger.info(f"  Effective batch size: {training_args.per_device_train_batch_size * training_args.gradient_accumulation_steps}")
    logger.info(f"  Learning rate: {training_args.learning_rate}")
    logger.info(f"  Max sequence length: 2048")
    logger.info(f"  Output: {LORA_OUTPUT_DIR}")
    print_separator()

    train_start = time.time()

    try:
        trainer.train()
    except torch.cuda.OutOfMemoryError:
        logger.error(
            "CUDA OUT OF MEMORY during training. "
            "Try reducing max_seq_length or ensure all GPU services are stopped."
        )
        return False
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise

    elapsed = time.time() - train_start
    minutes = elapsed / 60

    # ── Save adapter ───────────────────────────────────────────────────
    adapter_path = LORA_OUTPUT_DIR / "final_adapter"
    trainer.save_model(str(adapter_path))
    tokenizer.save_pretrained(str(adapter_path))

    logger.info(f"Training complete in {minutes:.1f} minutes.")
    logger.info(f"LoRA adapter saved to: {adapter_path}")

    vram_end = get_vram_free_mb()
    logger.info(f"VRAM after training: {vram_end:.0f} MB free")

    # Cleanup temp formatted file
    if formatted_path.exists():
        formatted_path.unlink()

    print_separator()
    print(f"  TRAINING COMPLETE")
    print(f"  Duration:     {minutes:.1f} minutes")
    print(f"  Examples:     {len(formatted)}")
    print(f"  Adapter:      {adapter_path}")
    print_separator()

    return True


# ========================================================================
#  Stage 3: MERGE
# ========================================================================

def stage_merge():
    """Merge LoRA adapter with base model and save full weights."""
    print_banner("STAGE 3 — MERGE")

    adapter_path = LORA_OUTPUT_DIR / "final_adapter"
    if not adapter_path.exists():
        logger.error(f"No LoRA adapter found at {adapter_path}. Run --train first.")
        return False

    # Check prerequisites
    for pkg in ["torch", "transformers", "peft"]:
        if not check_package_installed(pkg):
            logger.error(f"Required package '{pkg}' is not installed.")
            return False

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel

    # ── Free VRAM ──────────────────────────────────────────────────────
    logger.info("Stopping GPU services for merge...")
    try:
        run_cmd("systemctl --user stop joshua-voice", check=False, timeout=15)
        run_cmd("ollama stop joshua:latest", check=False, timeout=15)
    except Exception:
        pass
    time.sleep(3)

    # ── Load base model (full precision for merge) ─────────────────────
    logger.info(f"Loading base model for merge: {HF_MODEL_ID}")
    logger.info("This requires loading the full fp16 model (~14 GB RAM)...")

    model = AutoModelForCausalLM.from_pretrained(
        HF_MODEL_ID,
        torch_dtype=torch.float16,
        device_map="cpu",  # Merge on CPU to avoid VRAM limits
    )

    tokenizer = AutoTokenizer.from_pretrained(HF_MODEL_ID)
    tokenizer.pad_token = tokenizer.eos_token

    # ── Load and merge LoRA adapter ────────────────────────────────────
    logger.info(f"Loading LoRA adapter from: {adapter_path}")
    model = PeftModel.from_pretrained(model, str(adapter_path))

    logger.info("Merging LoRA weights into base model...")
    model = model.merge_and_unload()

    # ── Save merged model ──────────────────────────────────────────────
    MERGED_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Saving merged model to: {MERGED_OUTPUT_DIR}")

    model.save_pretrained(str(MERGED_OUTPUT_DIR))
    tokenizer.save_pretrained(str(MERGED_OUTPUT_DIR))

    logger.info("Merged model saved successfully.")

    print_separator()
    print("  MERGE COMPLETE")
    print(f"  Merged model: {MERGED_OUTPUT_DIR}")
    print()
    print("  Ollama 0.16+ supports direct safetensors import with --experimental.")
    print("  Run --import-model to import directly (no GGUF conversion needed).")
    print_separator()

    return True


# ========================================================================
#  Stage 4: IMPORT TO OLLAMA
# ========================================================================

def stage_import():
    """Create Ollama modelfile and import the fine-tuned model."""
    print_banner("STAGE 4 — IMPORT TO OLLAMA")

    # Look for GGUF file
    gguf_candidates = list(PROJECT_DIR.glob("*.gguf")) + list(MERGED_OUTPUT_DIR.glob("*.gguf"))

    gguf_path = None
    for candidate in gguf_candidates:
        if "wopr" in candidate.name.lower() or "cybersec" in candidate.name.lower():
            gguf_path = candidate
            break
    if not gguf_path and gguf_candidates:
        gguf_path = gguf_candidates[0]

    # If no GGUF, check if merged model exists for safetensors-based Modelfile
    has_merged = MERGED_OUTPUT_DIR.exists() and any(MERGED_OUTPUT_DIR.glob("*.safetensors"))

    if not gguf_path and not has_merged:
        logger.error(
            "No GGUF file or merged model found. "
            "Run --merge first, then quantize to GGUF."
        )
        return False

    # ── Build Modelfile ────────────────────────────────────────────────
    from config import SYSTEM_PROMPT

    if gguf_path:
        model_source = str(gguf_path)
        logger.info(f"Using GGUF model: {gguf_path}")
    else:
        model_source = str(MERGED_OUTPUT_DIR)
        logger.info(f"Using merged model directory: {MERGED_OUTPUT_DIR}")

    # Escape the system prompt for the Modelfile (handle triple-quotes and newlines)
    escaped_prompt = SYSTEM_PROMPT.replace('"""', '\\"\\"\\"')

    modelfile_content = f'''FROM {model_source}

PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER num_ctx 4096
PARAMETER num_predict 2048
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|im_start|>"

TEMPLATE """<|im_start|>system
{{{{ .System }}}}<|im_end|>
<|im_start|>user
{{{{ .Prompt }}}}<|im_end|>
<|im_start|>assistant
"""

SYSTEM """{SYSTEM_PROMPT}"""
'''

    with open(MODELFILE_PATH, "w", encoding="utf-8") as f:
        f.write(modelfile_content)

    logger.info(f"Modelfile written to: {MODELFILE_PATH}")

    # ── Create Ollama model ────────────────────────────────────────────
    logger.info(f"Creating Ollama model: {OLLAMA_FINETUNE_TAG}")

    # Use --experimental for safetensors + --quantize q4_0 (Ollama 0.16+)
    extra_flags = ""
    if has_merged and not gguf_path:
        extra_flags = " --experimental --quantize q4_0"
        logger.info("Using Ollama experimental safetensors import with Q4_0 quantization.")

    try:
        result = run_cmd(
            f"ollama create {OLLAMA_FINETUNE_TAG} -f {MODELFILE_PATH}{extra_flags}",
            check=True, timeout=900,
        )
        logger.info(f"Ollama model created: {OLLAMA_FINETUNE_TAG}")
        if result.stdout.strip():
            print(f"  Ollama output: {result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Ollama create failed: {e.stderr}")
        if has_merged and not gguf_path:
            logger.info("Tip: If experimental import fails, convert to GGUF manually:")
            logger.info(f"  python llama.cpp/convert_hf_to_gguf.py {MERGED_OUTPUT_DIR} "
                       f"--outfile {PROJECT_DIR}/wopr_cybersec.gguf --outtype q4_0")
        return False
    except subprocess.TimeoutExpired:
        logger.error("Ollama create timed out (15 min limit).")
        return False

    # ── Restart F5-TTS ─────────────────────────────────────────────────
    logger.info("Restarting F5-TTS voice server...")
    try:
        run_cmd("systemctl --user start joshua-voice", check=False, timeout=15)
        logger.info("F5-TTS voice server restarted.")
    except Exception as e:
        logger.warning(f"Could not restart F5-TTS: {e}")

    # ── Verify ─────────────────────────────────────────────────────────
    try:
        result = run_cmd("ollama list", check=True, timeout=15)
        if OLLAMA_FINETUNE_TAG.replace(":", " ") in result.stdout or "cybersec" in result.stdout:
            logger.info(f"Verified: {OLLAMA_FINETUNE_TAG} appears in ollama list.")
        else:
            logger.warning(f"Could not verify {OLLAMA_FINETUNE_TAG} in ollama list.")
    except Exception:
        pass

    print_separator()
    print(f"  IMPORT COMPLETE")
    print(f"  Model tag:  {OLLAMA_FINETUNE_TAG}")
    print(f"  Modelfile:  {MODELFILE_PATH}")
    print()
    print(f"  To use the fine-tuned model, update JOSHUA_MODEL:")
    print(f"    export JOSHUA_MODEL={OLLAMA_FINETUNE_TAG}")
    print(f"  Or run directly:")
    print(f"    ollama run {OLLAMA_FINETUNE_TAG}")
    print_separator()

    return True


# ========================================================================
#  Stage 5: STATUS
# ========================================================================

def stage_status():
    """Display training pipeline status overview."""
    print_banner("STATUS REPORT")

    # ── Training data ──────────────────────────────────────────────────
    print("  TRAINING DATA")
    print("  " + "-" * 50)

    curated_count = count_jsonl_lines(CURATED_DATASET)
    curated_exists = CURATED_DATASET.exists()
    print(f"  Curated dataset:  {'FOUND' if curated_exists else 'NOT FOUND'}")
    if curated_exists:
        print(f"    Path:     {CURATED_DATASET}")
        print(f"    Examples: {curated_count}")
    print()

    blackboard_files = sorted(TRAINING_DATA_DIR.glob("wopr_training_*.jsonl"))
    blackboard_total = 0
    print(f"  Blackboard exports: {len(blackboard_files)} files")
    for bf in blackboard_files:
        bc = count_jsonl_lines(bf)
        blackboard_total += bc
        mod_time = datetime.fromtimestamp(bf.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        print(f"    {bf.name}: {bc} examples ({mod_time})")
    print()

    total = curated_count + blackboard_total
    print(f"  TOTAL EXAMPLES: {total}")
    print(f"    Curated:    {curated_count}")
    print(f"    Blackboard: {blackboard_total}")
    print()

    # ── Artifacts ──────────────────────────────────────────────────────
    print("  ARTIFACTS")
    print("  " + "-" * 50)

    adapter_path = LORA_OUTPUT_DIR / "final_adapter"
    adapter_exists = adapter_path.exists()
    print(f"  LoRA adapter:   {'FOUND' if adapter_exists else 'NOT FOUND'}")
    if adapter_exists:
        print(f"    Path: {adapter_path}")
        # Check for adapter config
        adapter_config = adapter_path / "adapter_config.json"
        if adapter_config.exists():
            try:
                with open(adapter_config) as f:
                    cfg = json.load(f)
                print(f"    Rank (r): {cfg.get('r', '?')}")
                print(f"    Alpha:    {cfg.get('lora_alpha', '?')}")
            except Exception:
                pass

    merged_exists = MERGED_OUTPUT_DIR.exists() and any(MERGED_OUTPUT_DIR.glob("*.safetensors"))
    print(f"  Merged model:   {'FOUND' if merged_exists else 'NOT FOUND'}")
    if merged_exists:
        print(f"    Path: {MERGED_OUTPUT_DIR}")
        # Estimate size
        total_size = sum(f.stat().st_size for f in MERGED_OUTPUT_DIR.iterdir() if f.is_file())
        print(f"    Size: {total_size / (1024**3):.1f} GB")

    gguf_files = list(PROJECT_DIR.glob("*.gguf"))
    print(f"  GGUF files:     {len(gguf_files)} found")
    for gf in gguf_files:
        print(f"    {gf.name} ({gf.stat().st_size / (1024**3):.1f} GB)")

    print()

    # ── Ollama model check ─────────────────────────────────────────────
    print("  OLLAMA MODELS")
    print("  " + "-" * 50)

    try:
        result = run_cmd("ollama list", check=True, timeout=15)
        lines = result.stdout.strip().split("\n")
        for line in lines:
            if "joshua" in line.lower():
                print(f"    {line.strip()}")
        if not any("joshua" in line.lower() for line in lines):
            print("    No joshua models found in Ollama.")
    except Exception as e:
        print(f"    Could not query Ollama: {e}")

    print()

    # ── VRAM status ────────────────────────────────────────────────────
    print("  GPU STATUS")
    print("  " + "-" * 50)
    vram_free = get_vram_free_mb()
    vram_total = get_vram_total_mb()
    if vram_total > 0:
        vram_used = vram_total - vram_free
        pct = 100 * vram_used / vram_total
        print(f"    VRAM: {vram_used:.0f} / {vram_total:.0f} MB ({pct:.0f}% used)")
        print(f"    Free: {vram_free:.0f} MB")
        if vram_free >= 7000:
            print(f"    Training: READY (sufficient VRAM)")
        else:
            print(f"    Training: INSUFFICIENT (need ~7 GB free, stop GPU services first)")
    else:
        print("    VRAM: Could not query nvidia-smi")

    print()
    print_separator()

    return True


# ========================================================================
#  Main
# ========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="W.O.P.R. QLoRA Fine-Tuning Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Stages:
  --export        Export training data from Blackboard
  --train         QLoRA fine-tuning (requires GPU)
  --merge         Merge LoRA adapter with base model
  --import-model  Import fine-tuned model to Ollama
  --full          Run all stages sequentially
  --status        Show pipeline status report

Examples:
  python finetune_wopr.py --status
  python finetune_wopr.py --export --train
  python finetune_wopr.py --full
        """,
    )

    parser.add_argument("--export", action="store_true", help="Export Blackboard training data")
    parser.add_argument("--train", action="store_true", help="Run QLoRA fine-tuning")
    parser.add_argument("--merge", action="store_true", help="Merge LoRA adapter with base model")
    parser.add_argument("--import-model", action="store_true", help="Import model to Ollama")
    parser.add_argument("--full", action="store_true", help="Run all stages")
    parser.add_argument("--status", action="store_true", help="Show pipeline status")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # If no args, show help
    if not any([args.export, args.train, args.merge, args.import_model, args.full, args.status]):
        parser.print_help()
        return 1

    print()
    print("=" * 60)
    print("  W.O.P.R. QLoRA FINE-TUNING PIPELINE")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    success = True

    if args.status:
        stage_status()
        return 0

    if args.full or args.export:
        if not stage_export():
            if args.full:
                logger.error("Export stage failed. Aborting pipeline.")
                return 1
            success = False

    if args.full or args.train:
        if not stage_train():
            if args.full:
                logger.error("Training stage failed. Aborting pipeline.")
                return 1
            success = False

    if args.full or args.merge:
        if not stage_merge():
            if args.full:
                logger.error("Merge stage failed. Aborting pipeline.")
                return 1
            success = False

    if args.full or args.import_model:
        if not stage_import():
            if args.full:
                logger.error("Import stage failed. Aborting pipeline.")
                return 1
            success = False

    print()
    if success:
        print("  ALL REQUESTED STAGES COMPLETED SUCCESSFULLY.")
    else:
        print("  PIPELINE COMPLETED WITH ERRORS. Review logs above.")
    print("=" * 60)
    print()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
