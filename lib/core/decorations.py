# 用于定义装饰器
from functools import wraps
from flask import session, redirect, url_for


# 定义限制登录的装饰器，即点击前先判断session id是否传入
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if session.get('user_id'):
            return func(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return wrapper

