# 用于编写模型与数据库中表的映射
# 导入SQLAlchemy实例
from exts import db
# 导入对密码进行处理的扩展
from werkzeug.security import generate_password_hash, check_password_hash


# 创建表模型
class User(db.Model):
    # autoincrement表示自增
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # nullable为False表示不允许有空值
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    # 定义关系，第一个参数为模板名即类名，第二个表示当通过另一个表进行引用本表时的参数
    # 即要知道某个用户创建的任务可以通过user.tasks来获取
    tasks = db.relationship('Tasks', backref=db.backref('owner'))

    def __init__(self, *args, **kwargs):
        # 拦截用户数据
        username = kwargs.get('username')
        password = kwargs.get('password')
        # 给类变量进行赋值
        self.username = username
        # 对密码进行hash加密
        self.password = generate_password_hash(password)

    # 定义检查密码是否正确的函数
    def check_password(self, raw_password):
        # check_password_hash函数检查哈希密码和明文密码是否相同，相同则返回True，否则返回False
        return check_password_hash(self.password, raw_password)


class Tasks(db.Model):
    task_id = db.Column(db.String(40), primary_key=True)
    task_status = db.Column(db.String(11), nullable=False)
    task_data = db.Column(db.String(5000))
    # task_owner为外键，需要使用db.ForeignKey('表名.列名')指定
    task_owner_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))