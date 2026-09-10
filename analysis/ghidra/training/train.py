#!/usr/bin/env python3
"""Unsloth QLoRA training skeleton (#3080, round 7 / #3079, plan §3/§5/§10).

Runs inside the pinned container from compose.yaml -- never on the host.
Argument-driven on purpose: this round trains three different students (T1-T6
in the plan), and this skeleton must not hardcode any of them. Each concrete
run (#3083/#3084/#3085/#3088) passes its own --base-model / --dataset.

Writes a merged_16bit checkpoint (never merged_4bit -- lossy, Unsloth's own
warning) plus the Modelfile export_to_ollama.sh diffs against the base tag.

Operational copy lives at /var/benchmarks/round7/train.py.
"""
import argparse
import json
import sys
from datetime import datetime, timezone


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-model", required=True, help="HF repo id or local path, e.g. unsloth/Qwen3-14B-unsloth-bnb-4bit")
    p.add_argument("--dataset", required=True, help="path to a JSONL dataset (prompt/response or chat-format rows)")
    p.add_argument("--output-dir", required=True, help="where the merged_16bit export and Modelfile land")
    p.add_argument("--epochs", type=float, default=1.0)
    p.add_argument("--learning-rate", type=float, default=2e-4)
    p.add_argument("--max-seq-length", type=int, default=8192)
    p.add_argument("--lora-r", type=int, default=16)
    p.add_argument("--lora-alpha", type=int, default=16)
    p.add_argument("--seed", type=int, default=3407)
    p.add_argument("--train-on-responses-only", action="store_true", default=True)
    return p.parse_args(argv)


def load_model(args):
    from unsloth import FastLanguageModel

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.base_model,
        max_seq_length=args.max_seq_length,
        load_in_4bit=True,
        dtype=None,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        use_gradient_checkpointing="unsloth",
        random_state=args.seed,
    )
    return model, tokenizer


def build_trainer(args, model, tokenizer, dataset):
    from trl import SFTConfig, SFTTrainer
    from unsloth.chat_templates import train_on_responses_only

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        args=SFTConfig(
            per_device_train_batch_size=2,
            gradient_accumulation_steps=4,
            num_train_epochs=args.epochs,
            learning_rate=args.learning_rate,
            optim="adamw_8bit",
            seed=args.seed,
            output_dir=args.output_dir + "/checkpoints",
        ),
    )
    if args.train_on_responses_only:
        trainer = train_on_responses_only(trainer)
    return trainer


def main(argv=None):
    args = parse_args(argv)

    from datasets import load_dataset

    dataset = load_dataset("json", data_files=args.dataset, split="train")

    model, tokenizer = load_model(args)
    trainer = build_trainer(args, model, tokenizer, dataset)

    run_started = datetime.now(timezone.utc).isoformat()
    stats = trainer.train()
    run_finished = datetime.now(timezone.utc).isoformat()

    # never merged_4bit -- lossy (plan §10); export_to_ollama.sh assumes 16-bit
    model.save_pretrained_merged(args.output_dir, tokenizer, save_method="merged_16bit")

    with open(f"{args.output_dir}/train_run.json", "w") as f:
        json.dump(
            {
                "base_model": args.base_model,
                "dataset": args.dataset,
                "epochs": args.epochs,
                "learning_rate": args.learning_rate,
                "max_seq_length": args.max_seq_length,
                "lora_r": args.lora_r,
                "lora_alpha": args.lora_alpha,
                "seed": args.seed,
                "started": run_started,
                "finished": run_finished,
                "train_loss": getattr(stats, "training_loss", None),
            },
            f,
            indent=2,
        )

    print(f"merged_16bit checkpoint written to {args.output_dir}")


if __name__ == "__main__":
    sys.exit(main())
