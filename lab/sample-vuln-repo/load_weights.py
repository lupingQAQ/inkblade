"""权重/检查点加载样本（实验室 fixture）：不安全反序列化演示。"""
import importlib
import pickle

import torch


def load_checkpoint(path):
    return torch.load(path, map_location="cpu", weights_only=False)


def load_rollout(path):
    with open(path, "rb") as fh:
        return pickle.loads(fh.read())


def load_trajectory_legacy(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)


def load_extension(name):
    return importlib.import_module(name)  # 用户输入直达动态导入
