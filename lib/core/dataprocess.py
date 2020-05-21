# 数据处理模块，将与扫描任务相关的数据存储到数据库中
import json
from flask import session
from models import Tasks
from exts import db
from scripts.PortScan import PortScan, multithreading_port_scan
"""
任务在完成之前，扫描结果字段只存储了target部分即{"target": "192.168.1.9"}
"""

class DataProcess(object):
    def __init__(self, task_object):
        self.task = task_object

    # 将数据存储到数据库
    def store_to_database(self):
        taskid_json = self.task.taskid  # 任务id str格式
        task_status_json = self.task.status  # 任务状态 str格式
        task_result_json = json.dumps(self.task.task_result)  # 任务结果 json格式
        task_owner_id = session.get('user_id')  # 任务创建者 int类型
        # 实例化数据对象
        task = Tasks(task_id=taskid_json, task_status=task_status_json, task_data=task_result_json, task_owner_id=task_owner_id)
        db.session.add(task)  # 将数据对象添加到数据库
        db.session.commit()  # 提交事务

    # 修改任务状态 status为字符串
    def alter_data(self, result=None, status=None):
        res = Tasks.query.filter(Tasks.task_id == self.task.taskid).first()  # 查找当前任务id的数据
        if status is not None:
            res.task_status = status  # 修改任务状态
        if result is not None:
            res.task_data = json.dumps(result)  # 修改任务结果
        db.session.commit()  # 提交事务

    # 从数据库中tasks表中获取所有数据，返回{"任务id":{"task_status": task_status, "task_data": task_data, "task_owner_id": task_owner_id}}
    @staticmethod
    def select_data():
        res = Tasks.query.filter().all()
        tasks = {}
        for i in res:
            tasks[i.task_id] = {"task_status": i.task_status,
                                "task_type": json.loads(i.task_data)['task_type'],
                                "task_data": json.loads(i.task_data),
                                "task_owner_id": i.task_owner_id}
        return tasks

    # 查找指定任务id的数据
    @staticmethod
    def select_specify_task(task_id):
        res = Tasks.query.filter(Tasks.task_id == task_id).first()
        task = {'task_id': res.task_id, 'task_status': res.task_status, 'task_data': json.loads(res.task_data),
                'task_owner_id': res.task_owner_id}
        return task

    # 删除指定id的数据
    @staticmethod
    def delete_task(task_id):
        res = Tasks.query.filter(Tasks.task_id == task_id).first()
        db.session.delete(res)
        db.session.commit()
    # 添加用户
    # @app.route('/useradd', methods=['GET', 'POST'])
    # def useradd():
    #     username = User(username="aaa", password="aaa")
    #     db.session.add(username)
    #     db.session.commit()
    #     return "用户添加成功！"


if __name__ == '__main__':
    pass