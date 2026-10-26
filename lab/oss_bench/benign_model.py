"""Benign pickle target for the OSS scanner bench (unknown-global false-positive control).

The class is importable so a scanner can resolve the global reference; it has no
``__reduce__`` and performs no I/O.
"""


class SimpleModel:
    def __init__(self, input_dim: int = 4, hidden_dim: int = 8):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.weights = []

    def forward(self, value: float) -> float:
        return value * sum(self.weights)
