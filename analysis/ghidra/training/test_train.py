#!/usr/bin/env python3
"""Smoke test for train.py's argument parsing -- no GPU, no Unsloth import."""
from train import parse_args


def test_required_args_and_defaults():
    args = parse_args([
        "--base-model", "unsloth/Qwen3-14B-unsloth-bnb-4bit",
        "--dataset", "/workspace/corpus-round7/s2_train.jsonl",
        "--output-dir", "/workspace/runs/t2-qwen3-14b",
    ])
    assert args.base_model == "unsloth/Qwen3-14B-unsloth-bnb-4bit"
    assert args.epochs == 1.0
    assert args.max_seq_length == 8192
    assert args.train_on_responses_only is True


def test_missing_required_arg_exits():
    try:
        parse_args(["--dataset", "x", "--output-dir", "y"])
    except SystemExit as e:
        assert e.code != 0
    else:
        raise AssertionError("expected SystemExit for missing --base-model")


if __name__ == "__main__":
    test_required_args_and_defaults()
    test_missing_required_arg_exits()
    print("ok")
