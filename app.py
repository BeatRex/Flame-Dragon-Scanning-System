#!/usr/bin/python3
import threading

from flask import Flask, render_template, request, flash, session, redirect, url_for
# 导入模型，即导入定义好的数据表的类
from models import User
# 导入SQLAlchemy db
from exts import db
# 导入配置文件
import config
# 导入装饰器文件
from lib.core.decorations import login_required
# 导入url爬取模块
from scripts.Crawl import Crawler
# 导入端口扫描模块
from scripts.PortScan import PortScan, domain2ip, get_port_queue, multithreading_port_scan
# 导入SQL注入检测插件(即编写的处理与sqlmapapi交互的类SQLIchecker)
from scripts.SQLIkiller import SQLIchecker
# 导入XSS检测插件
from scripts.XSSkiller import XSSchecker
# 导入数据处理模块
from lib.core.dataprocess import DataProcess
# 导入其他模块
import time
import requests
import json
import multiprocessing

# 创建flask实例
app = Flask(__name__)

# 导入配置
app.config.from_object(config)
# 定义实例属性
app.secret_key = 'test'

# 初始化db
db.init_app(app)

# 定义路由及视图函数


# ----------------------- 扫描器页面功能部分视图函数定义 -----------------------
# 扫描器主页面(登录过后)
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    return render_template('index.html')

# 添加用户
@app.route('/useradd', methods=['GET', 'POST'])
def useradd():
    if request.method == "GET":
        return render_template('useradd.html')
    else:
        usr = request.form.get('username')
        psd = request.form.get('password')
    username = User(username=usr, password=psd)
    db.session.add(username)
    db.session.commit()
    return redirect(url_for('login'))


# 登录界面
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 根据请求的方法返回不同的页面
    if request.method == "GET":
        return render_template('login.html')
    else:
        # 获取用户名及密码
        usr = request.form.get('username')
        psd = request.form.get('password')
        # 在数据库中查询用户名
        user = User.query.filter(User.username == usr).first()
        # 若用户存在并且密码与数据库中存储的hash加密结果对比成功则说明输入正确
        if user and user.check_password(psd):
            session['user_id'] = user.user_id
            return redirect(url_for('index'))
        else:
            alert_class = "alert alert-danger"
            flash("用户名或密码错误！")
            return render_template('login.html', alert_class=alert_class)


# 注销功能
@app.route('/logout', methods=['GET'])
def logout():
    # 清除session并返回到登录界面
    session.clear()
    return redirect(url_for('login'))


# 关于扫描器介绍的页面
@app.route('/about', methods=['GET', 'POST'])
@login_required
def about():
    return render_template('about.html')


# ----------------------- 扫描器安全部分视图函数定义 -----------------------
# 页面爬取视图函数
@app.route('/crawl', methods=['GET', 'POST'])
@login_required
def crawl():
    if request.method == "GET":  # 判断请求方法
        return render_template('crawl.html')
    else:
        target_url = request.form.get('url')  # 从表单获取待爬取的目标url
        is_crawl_total = request.form.get('crawl_total')  # 从表单获取是否爬取整站的选项 若未选中则返回None，选中返回totalSite即标签的value值
        new_task = Crawler(target_url)  # 实例化任务
        task_data_process = DataProcess(new_task)  # 实例化数据处理对象
        task_data_process.store_to_database()
        if is_crawl_total is None:  # 判断是否选择了整站爬取
            task_data_process.alter_data(status="running")  # 将状态改为正在扫描
            new_task.url_crawl_one()  # 调用爬取单页的方法
            # time.sleep(3)  # 测试
            task_data_process.alter_data(result=new_task.task_result, status="terminated")  # 将状态改为扫描结束 并将扫描结果进行修改
        elif is_crawl_total == "totalSite":
            task_data_process.alter_data(status="running")  # 将状态改为正在扫描
            new_task.url_crawl_total()  # 调用爬取整站的方法
            # time.sleep(3)  # 测试
            task_data_process.alter_data(result=new_task.task_result, status="terminated")  # 将状态改为扫描结束 并将扫描结果进行修改
        return redirect(url_for('task_list'))


# 端口扫描视图函数
@app.route('/portscan', methods=['GET', 'POST'])
@login_required
def port_scan():
    if request.method == "GET":
        return render_template('portScan.html')
    else:
        ip = request.form.get('ip')  # 接收ip
        port_range_queue = request.form.get('port')  # 接收端口范围
        threads = request.form.get('thread')  # 接收线程
        scan_mode = request.form.get('mode')  # 获取扫描的方式
        # 【待完善】 对输入数据做过滤检测：端口范围仅允许输入指定类型，对指定类型进行检测，处理端口范围的函数仅支持指定类型的匹配
        # ------------------------------------
        if ip.startswith("http"):  # 判断目标是域名还是ip，若为域名则进行解析
            ip = domain2ip(ip)  # 参数只能传入http(s)://www.example.com格式，末尾不能添加/

        # 处理用户指定的端口范围
        if port_range_queue != "":
            port_range_queue = get_port_queue(port_range_queue)

        # 判断线程 默认设置为5，若用户指定则将接收到的threads(str类型)转换为int类型重新赋值给threads
        if threads == "":
            threads = 5
        else:
            threads = int(threads)

        # 实例化端口扫描对象
        new_task = PortScan(ip)
        new_task.create_port_scan_task()  # 创建任务即生成taskid

        task_data_process = DataProcess(new_task)  # 实例化数据处理对象
        task_data_process.store_to_database()  # 将当前的任务信息存储到数据库中

        # 根据用户指定的方式进行扫描
        if scan_mode == "基于socket":  # socket方式扫描
            scan_mode = "SOCKET"
        elif scan_mode == "基于TCP-SYN半开式":  # TCP-SYN半开式扫描
            scan_mode = "TCP"
        else:  # UDP扫描
            scan_mode = "UDP"
        flash("任务创建成功!")  # 返回任务创建成功的提示信息

        # 开启一个进程实现多任务
        new_process = multiprocessing.Process(target=multithreading_port_scan, args=(new_task, port_range_queue, threads, scan_mode, task_data_process))  # 实例化进程对象
        new_process.run()  # 开启进程
        return redirect(url_for('task_list'))


# SQL注入检测视图函数
@app.route('/sqlikiller', methods=['GET', 'POST'])
@login_required
def sqli_scan():
    if request.method == "GET":  # 如果GET请求则返回表单页面
        return render_template('sqliScan.html')
    else:  # 如果POST请求则进行后台表单处理
        # 未填写的部分变量接收为空，即"" 如post数据未填写，post_data变量接收到的就为""
        target_url = request.form.get('url')  # 获取目标url
        post_data = request.form.get('postData')  # 获取post数据
        referer_data = request.form.get('referer')  # 获取referer数据
        ua_data = request.form.get('userAgent')  # 获取User-Agent的值
        cookie_sqli_data = request.form.get('cookie_sqli')  # 获取cookie注入检测的值
        request_cookie = request.form.get('cookie')  # 获取访问请求时携带的cookie
        task_threads = request.form.get('thread')  # 获取线程，如果未传入线程参数则将其默认设置为1
        if task_threads == "":
            task_threads = 1

        # 实例化一个SQLchecker对象用户创建任务
        new_task = SQLIchecker(target_url=target_url)

        # 实例化数据处理对象
        task_data_process = DataProcess(new_task)

        flash("任务创建成功！")  # 返回页面任务创建成功的提示信息

        return redirect(url_for('task_list'))


# XSS扫描
@app.route('/xsskiller', methods=['GET', 'POST'])
@login_required
def xss_scan():
    if request.method == "GET":
        return render_template('xssScan.html')
    else:
        target_url = request.form.get('url')
        post_data = request.form.get('postData')
        request_cookie = request.form.get('Cookie')
        # print(target_url)
        # print(post_data)  # 未填写则为空
        # print(request_cookie)
        new_task = XSSchecker(url=target_url, cookie=request_cookie, data=post_data)  # 实例化XSS检测对象

        task_data_process = DataProcess(new_task)  # 实例化数据处理对象
        task_data_process.store_to_database()  # 将当前的任务信息存储到数据库中

        flash("任务创建成功!")  # 返回任务创建成功的提示信息
        task_data_process.alter_data(status="running")  # 将状态改为正在扫描
        new_task.start_task()  # 开启扫描

        task_result = new_task.task_result  # 获取扫描结果

        task_data_process.alter_data(result=new_task.task_result, status="terminated")  # 将状态改为扫描结束 并将扫描结果进行修改
        print(task_result)
        return redirect(url_for('task_list'))


# 任务列表
@app.route('/tasklist', methods=['GET', 'POST'])
@login_required
def task_list():
    tasks = DataProcess.select_data()
    # print(tasks)
    return render_template('tasklist.html', tasks=tasks)


# 报告输出及下载
@app.route('/result/<task_id>', methods=['GET'])
@login_required
def result(task_id):
    # print(task_id)
    task = DataProcess.select_specify_task(task_id)
    print(task)
    return render_template('result.html', task=task)


# 删除任务
@app.route('/delete/<task_id>')
@login_required
def delete(task_id):
    # 删除操作
    DataProcess.delete_task(task_id)
    return redirect(url_for('task_list'))


if __name__ == '__main__':
    app.run()
