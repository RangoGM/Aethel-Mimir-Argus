"""
MIMIR QLoRA Fine-tuning with Unsloth
Hardware: RTX 3060 12GB
Model: LLaMA 3 8B → MIMIR fine-tuned
Dataset: 240 samples (admin_dataset.json)

Install first:
  pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
  pip install --no-deps xformers trl peft accelerate bitsandbytes triton
"""

from unsloth import FastLanguageModel
import os
import torch, json

MAX_SEQ_LENGTH = 4096
DTYPE = None  
LOAD_IN_4BIT = True  
DATASET_FILE = os.environ.get("MIMIR_DATASET", "dataset_unsloth.json")
OUTPUT_DIR = os.environ.get("MIMIR_OUTPUT_DIR", "outputs_mimir")
GGUF_OUTPUT_DIR = os.environ.get("MIMIR_GGUF_OUTPUT", "mimir-finetuned")
TRAIN_EPOCHS = float(os.environ.get("MIMIR_EPOCHS", "3"))

print("Loading base LLaMA 3 8B...")
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="unsloth/llama-3-8b-bnb-4bit", 
    max_seq_length=MAX_SEQ_LENGTH,
    dtype=DTYPE,
    load_in_4bit=LOAD_IN_4BIT,
)

print("Adding QLoRA adapters...")
model = FastLanguageModel.get_peft_model(
    model,
    r=16,               
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                    "gate_proj", "up_proj", "down_proj"],
    lora_alpha=16,
    lora_dropout=0,     
    bias="none",
    use_gradient_checkpointing="unsloth",  
    random_state=42,
)

alpaca_prompt = """Below is an instruction that describes a task. Write a response that appropriately completes the request.

### Instruction:
{}

### Input:
{}

### Response:
{}"""

EOS_TOKEN = tokenizer.eos_token

def formatting_prompts_func(examples):
    instructions = examples["instruction"]
    inputs = examples["input"]
    outputs = examples["output"]
    texts = []
    for inst, inp, out in zip(instructions, inputs, outputs):
        text = alpaca_prompt.format(inst, inp, out) + EOS_TOKEN
        texts.append(text)
    return {"text": texts}

from datasets import load_dataset
dataset = load_dataset("json", data_files=DATASET_FILE, split="train")
dataset = dataset.map(formatting_prompts_func, batched=True)

print(f"Dataset loaded: {len(dataset)} samples from {DATASET_FILE}")

from trl import SFTTrainer
from transformers import TrainingArguments

print("Starting fine-tuning...")
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=MAX_SEQ_LENGTH,
    dataset_num_proc=2,
    packing=False,
    args=TrainingArguments(
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        warmup_steps=5,
        num_train_epochs=TRAIN_EPOCHS,
        learning_rate=2e-4,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=10,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="linear",
        seed=42,
        output_dir=OUTPUT_DIR,
        report_to="none",
    ),
)

gpu_stats = torch.cuda.get_device_properties(0)
used_memory = round(torch.cuda.max_memory_reserved() / 1024 / 1024 / 1024, 3)
print(f"GPU: {gpu_stats.name} ({gpu_stats.total_memory / 1024**3:.1f}GB)")
print(f"VRAM used before training: {used_memory}GB")

trainer_stats = trainer.train()
used_memory_after = round(torch.cuda.max_memory_reserved() / 1024 / 1024 / 1024, 3)
print(f"\nTraining complete!")
print(f"VRAM peak: {used_memory_after}GB")
print(f"Training time: {trainer_stats.metrics['train_runtime']:.0f}s")
print(f"Training loss: {trainer_stats.metrics['train_loss']:.4f}")
print("\nExporting to GGUF (Q4_K_M) for Ollama...")
model.save_pretrained_gguf(
    GGUF_OUTPUT_DIR,
    tokenizer,
    quantization_method="q4_k_m",
)

print("""
============================================
  DONE! Next steps:
============================================
1. Create Ollama model:
   ollama create mimir-finetuned -f Modelfile.mimir

2. Modelfile.mimir content:
   FROM ./mimir-finetuned-unsloth.Q4_K_M.gguf
   PARAMETER temperature 0.0
   PARAMETER num_ctx 4096
   ...

3. Test: ollama run mimir-finetuned

4. Run comparison: python test_comparison.py
============================================
""")
