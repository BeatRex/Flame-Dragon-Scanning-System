import uuid
import random
import threading
import time

# 生成taskid
def generate_taskid(num=1):
    a = uuid.uuid1()  # 根据 时间戳生成 uuid , 保证全球唯一
    c = str(a).replace("-", "")
    return c  # 返回随机字符串


if __name__ == '__main__':
    id = generate_taskid()
