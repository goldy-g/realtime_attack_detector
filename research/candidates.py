"""The models under test (2.8): newest small releases per lab, checked on Hugging Face on 2026-10-22,
plus three previous-generation models kept only as reference points."""

CANDIDATES = [
    # name, GGUF file, released, source repo, note. Parameter counts are read from the GGUF by llama-bench.
    ("Qwen3.5-4B", "Qwen3.5-4B-Q4_K_M.gguf", "2026-02", "unsloth/Qwen3.5-4B-GGUF", "hybrid linear attention"),
    ("Qwen3.5-2B", "Qwen3.5-2B-Q4_K_M.gguf", "2026-02", "unsloth/Qwen3.5-2B-GGUF", "hybrid linear attention"),
    ("Gemma-4-E4B", "gemma-4-E4B_q4_0-it.gguf", "2026-03", "google/gemma-4-E4B-it-qat-q4_0-gguf", "per-layer embeddings, QAT Q4_0"),
    ("Gemma-4-E2B", "gemma-4-E2B_q4_0-it.gguf", "2026-03", "google/gemma-4-E2B-it-qat-q4_0-gguf", "per-layer embeddings, QAT Q4_0"),
    ("Granite-4.2-8B", "granite-4.2-8b-Q4_K_M.gguf", "2026-08", "ibm-granite/granite-4.2-8b-GGUF", ""),
    ("Granite-4.2-3B", "granite-4.2-3b-Q4_K_M.gguf", "2026-08", "ibm-granite/granite-4.2-3b-GGUF", ""),
    ("LFM2.5-8B-A1B", "LFM2.5-8B-A1B-Q4_K_M.gguf", "2026", "LiquidAI/LFM2.5-8B-A1B-GGUF", "mixture of experts, conv + attention"),
    ("LFM2.5-2.6B", "LFM2.5-2.6B-Q4_K_M.gguf", "2026", "LiquidAI/LFM2.5-2.6B-GGUF", "conv + attention"),
    ("LFM2.5-1.2B", "LFM2.5-1.2B-Instruct-Q4_K_M.gguf", "2026", "LiquidAI/LFM2.5-1.2B-Instruct-GGUF", "conv + attention"),
    ("Nemotron-Dory-4B", "NVIDIA-Nemotron-Labs-Dory1.0-4B-Q5_K_M.gguf", "2026-10", "nvidia/NVIDIA-Nemotron-Labs-Dory1.0-4B-GGUF", "Q5_K_M (no Q4 published)"),
    ("Ministral-3-8B", "Ministral-3-8B-Instruct-2512-Q4_K_M.gguf", "2025-12", "mistralai/Ministral-3-8B-Instruct-2512-GGUF", ""),
    ("Ministral-3-3B", "Ministral-3-3B-Instruct-2512-Q4_K_M.gguf", "2025-12", "mistralai/Ministral-3-3B-Instruct-2512-GGUF", ""),
    ("Foundation-Sec-1.1-8B", "foundation-sec-1.1-8b-instruct-q4_k_m.gguf", "2025-11", "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF", "security-tuned Llama 3.1"),
    # previous generation, reference only
    ("Qwen3-4B-2507 (prev)", "Qwen3-4B-Instruct-2507-Q4_K_M.gguf", "2025-07", "unsloth/Qwen3-4B-Instruct-2507-GGUF", "reference"),
    ("Qwen3-1.7B (prev)", "Qwen3-1.7B-Q8_0.gguf", "2025-04", "Qwen/Qwen3-1.7B-GGUF", "reference, Q8_0"),
    ("LFM2-8B-A1B (prev)", "LFM2-8B-A1B-Q4_K_M.gguf", "2025-10", "LiquidAI/LFM2-8B-A1B-GGUF", "reference"),
]

UNSUPPORTED = {"Nemotron-Dory-4B": "llama.cpp build 11669: unknown model architecture 'dory'"}


def ready(gguf: str) -> bool:
    """True once a download log records the file as complete."""
    import glob
    import os
    from common import ROOT
    for log in glob.glob(os.path.join(ROOT, "models", "dl-*.log")):
        if any(line.split()[1:3] == ["done", gguf] for line in open(log, encoding="utf-8") if line.strip()):
            return True
    return False
