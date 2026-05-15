from unsloth import FastLanguageModel
import torch
import os

model_name = os.environ.get("MIMIR_CHECKPOINT", r"outputs_mimir\checkpoint-90")
export_output = os.environ.get("MIMIR_EXPORT_OUTPUT", "mimir_final_306")
max_seq_length = int(os.environ.get("MIMIR_EXPORT_SEQ_LEN", "2048"))

print(f"--- Inserting MIMIR brain from: {model_name} ---")

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = model_name,
    max_seq_length = max_seq_length,
    load_in_4bit = True,
)

try:
    print("--- Compressing MIMIR ---")
    model.save_pretrained_gguf(
        export_output,
        tokenizer, 
        quantization_method = "q4_k_m"
    )
    print("--- ✅ Success! ---")
    print(f"Your file: {export_output}-Q4_K_M.gguf")
except Exception as e:
    print(f"❌ Error: {e}")
