"""模型拉取样本（实验室 fixture）：trust_remote_code 硬编码 + revision 缺失 + file:// 接受。"""
from transformers import AutoModelForCausalLM, AutoTokenizer


def fetch(model_name, url):
    if url.startswith("file://"):  # 本地 file:// 直载
        path = url[len("file://"):]
        return AutoModelForCausalLM.from_pretrained(path, trust_remote_code=True)
    return AutoModelForCausalLM.from_pretrained(
        model_name, trust_remote_code=True
    )


def fetch_tokenizer(model_name):
    return AutoTokenizer.from_pretrained(model_name)  # revision 缺失
