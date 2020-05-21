#!/usr/bin/python3
# SQL注入检测插件
import time
"""
使用方法：一个对象仅可以扫描一个任务，创建多个任务需要创建多个对象
"""
import requests
import subprocess
import json


class SQLIchecker(object):
    headers = {'Content-Type': 'application/json',
               'Cookie': ''}

    def __init__(self, target_url):
        self.server = "http://127.0.0.1:8775"  # 定义sqlmapapi服务端的地址及ip
        self.target = target_url  # 默认为None，当用户传入url时将url赋值给target
        self.admin_token = "sqlmap for flame dragon"  # admin token
        self.taskid = requests.get("%s/task/new" % self.server).json()['taskid']  # 任务id
        self.task_type = "SQLI"  # 任务类型为sql注入扫描
        self.task_start_time = None  # 任务启动时间 格式为：2020-03-29 13:31:06
        self.status = "not running"  # 任务当前的状态not running为未开启，running正在扫描，terminated扫描结束
        self.task_result = {"task_type": "SQLI", "target": target_url}  # 格式化后的任务结果，键为sql注入title，值为相应的payload

    # 删除任务，删除成功返回True，未执行删除操作返回None
    def delete_task(self):
        if self.taskid is not None:
            r = requests.get("%s/task/%s/delete" % (self.server, self.taskid))
            return True
        return None

    # 开启任务：默认只检测GET型注入，传入url即可。任务开启成功返回值，失败返回False，未执行函数返回None
    # 如需检测post、referer等注入将相应的值传入函数即可
    def start_task(self, url, post="", referer="", cookie_sqli="", request_cookie="", user_agent="", threads=1, level=1):
        if self.taskid is not None:  # 判断是否创建了任务即taskid是否有值
            if request_cookie != "":  # 如果设置了登陆后访问的Cookie，将Cookie添加到请求头中
                self.headers['Cookie'] = request_cookie
            if cookie_sqli != "":  # 如果设置了检测cookie注入则需要将level的值改为2
                level = 2
            if user_agent != "":  # 如果设置了检测UA注入则需要将level的值改为3
                level = 3
            data = {
                'url': url,
                'data': post,
                'referer': referer,
                'cookie': cookie_sqli,
                'threads': threads,
                'level': level
            }
            r = requests.post("%s/scan/%s/start" % (self.server, self.taskid),
                              data=json.dumps(data),
                              headers=self.headers,
                              )
            if r.json()['success']:
                self.task_start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                self.status = "running"  # 任务开启成功后将任务的状态修改为running
                return r.json()['engineid']
            return False
        return None

    # 停止指定taskid的任务，停止成功返回True，失败返回Flse，未执行函数返回None
    def stop_task(self):
        if self.taskid is not None:
            r = requests.get("%s/scan/%s/stop" % (self.server, self.taskid))
            if r.json()['success']:
                self.status = "not running"
                return True
            return False
        return None

    # 获取任务扫描的状态，循环访问接口查询状态，若正在扫描则继续循环，扫描结束则返回True，扫描被停止返回False
    def get_task_status(self):
        if self.status == "running":  # 判断self.status即任务是否正在扫描，若任务正在扫描则循环判断状态并将结果赋值给当前任务状态属性self.status
            # print("--get_status")
            while True:
                current_status = requests.get("%s/scan/%s/status" % (self.server, self.taskid)).json()['status']
                if current_status == "terminated":
                    self.status = "terminated"
                    self.format_task_result()  # 扫描结束之后调用格式化扫描结果方法，将扫描结果进行格式化并返回到self.task_result
                    return True
                elif current_status == "running":
                    self.status = "running"
                elif current_status == "not running":
                    self.status = "not running"
                    return False
                time.sleep(2)  # 隔两秒循环一次

    # 获取扫描结果，存在注入返回结果，不存在返回None
    def task_data(self):
        if self.taskid is not None:
            r = requests.get("%s/scan/%s/data" % (self.server, self.taskid))
            if (r.json()['data']):
                return r.json()['data']
            else:
                return None

    # 格式化扫描结果 获取扫描结果并返回一个字典，键为place<=>parameter，值为相应类型的title<=>payload列表。返回None说明不存在注入
    def format_task_result(self):
        """格式化SQL注入扫描结果
        :return: {"<place>Cookie<parameter>ant[uname]":
                                    {序号0:
                                        {"title": title,
                                        "payload": payload}
                                    },
                                    {序号1:
                                        {"title": title,
                                        "payload": payload}
                                    }
                 }
        """
        task_data = self.task_data()
        if task_data:
            for sqli_place in task_data[1]['value']:  # 外层循环首先遍历每个注入点
                # 获取到当前注入点的place及parameter以元组(place, parameter)的格式保存
                place_and_param = sqli_place['place']
                # print(place_and_param)  # <place>Cookie<parameter>ant[uname]
                types = {}  # 定义一个字典用于存放当前注入点的每一种注入类型及payload
                type_num = 0  # 定义注入类型的序号，从0开始
                for sqli_type in sqli_place['data']:
                    title = sqli_place['data'][sqli_type]['title']  # 注入类型的title
                    payload = sqli_place['data'][sqli_type][
                        'payload']  # 注入类型的payload
                    types[type_num] = {
                        "title": title,
                        "payload": payload
                    }  # 将每一种注入类型添加到types字典中
                    type_num += 1
                # 最后返回一个字典，键为字符串<place>Cookie<parameter>ant[uname]，值为相应类型的{序号0:{"title": title, "payload": payload}}字典
                self.task_result[place_and_param] = types
            self.task_result["start_time"] = self.task_start_time
            return self.task_result
        return None

    # 主程序
    def main(self, data_process_object, post="", referer="", cookie_sqli="", request_cookie="", user_agent="", threads=1, level=1):
        print("任务开始")
        data_process_object.store_to_database()  # 将当前的任务信息存储到数据库
        print("将当前的任务信息存储到数据库")
        self.start_task(self.target, post=post, referer=referer, cookie_sqli=cookie_sqli, request_cookie=request_cookie, user_agent=user_agent, threads=threads)
        print("start_task")
        data_process_object.alter_data(status="running")  # 将状态改为正在扫描
        print("将状态改为正在扫描")
        self.get_task_status()
        print("获取状态")
        data_process_object.alter_data(result=self.task_result, status="terminated")  # 将状态改为扫描结束 并将扫描结果进行修改
        print("将状态改为扫描结束 并将扫描结果进行修改")


if __name__ == '__main__':
    start_server()
