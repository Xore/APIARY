import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

BASE = "unsloth/Qwen2.5-Coder-7B"
REV = "5762507e8ed2132906da60f86a2b23b54673ee81"
ADAPTER_DIR = "/work/REx86_adapter/REx86"

print("loading base...")
base = AutoModelForCausalLM.from_pretrained(
    BASE, revision=REV, torch_dtype=torch.float16, device_map="cuda:0"
)
tok = AutoTokenizer.from_pretrained(BASE, revision=REV)

print("applying adapter...")
merged = PeftModel.from_pretrained(base, ADAPTER_DIR)
merged = merged.merge_and_unload()

print("saving merged fp16 model...")
merged.save_pretrained("/work/rex86-merged", safe_serialization=True)
tok.save_pretrained("/work/rex86-merged")
print("done")
