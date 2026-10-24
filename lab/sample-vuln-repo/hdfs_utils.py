"""HDFS 数据装填样本（实验室 fixture）：路径拼接进入 os.system。"""
import os


def pull_dataset(hdfs_path):
    local = "/tmp/batch"
    os.system("hadoop fs -get " + hdfs_path + " " + local)  # 字符串拼接注入


def push_archive(hdfs_path, local_file):
    os.system(f"hadoop fs -put {local_file} {hdfs_path}")  # f-string 拼接注入
