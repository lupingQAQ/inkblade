"""训练栈样本（实验室 fixture）：预训练/SFT/RL 数据与训练编排 sink 演示。"""
import os
import subprocess

import torch
import yaml


def load_optimizer_state(path):
    return torch.load(path, map_location="cpu")


def load_train_config(path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.load(fh, Loader=yaml.FullLoader)


def render_system(tokenizer, messages):
    return tokenizer.apply_chat_template(messages, tokenize=False)


def launch_slurm(script):
    return subprocess.Popen(["sbatch", script])


def load_sft_data(path):
    return load_dataset("json", data_files=path)


def read_rank():
    return int(os.environ["LOCAL_RANK"])


def load_remote_class(model_args):
    return AutoModel.from_pretrained(
        model_args.model_name_or_path,
        trust_remote_code=model_args.trust_remote_code,
    )


def on_checkpoint_saved(run):
    wandb_utils.on_save_checkpoint_success(run)


def train_loop(world_size, rank):
    return f"world_size={world_size} rank={rank}"
