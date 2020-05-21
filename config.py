import os

# --------------------------配置session相关参数--------------------------------
SECRET_KEY = os.urandom(24)

# --------------------------配置数据库的相关参数--------------------------------
# 数据库的类型，如：MySQL、SQLlite、PostgreSQL等【名称为小写】
DIALECT = "mysql"
# Python对应的驱动，若不指定为数据库的默认驱动，如MySQL的驱动为MySQLdb
DRIVER = "mysqldb"
# 数据库的用户名
USERNAME = "root"
# 数据库的密码
PASSWORD = "root"
# 数据库的地址
HOST = "127.0.0.1"
# 数据库的端口
PORT = "3306"
# 数据库名
DATABASE = "flame_dragon"

SQLALCHEMY_DATABASE_URI = \
    "{}+{}://{}:{}@{}:{}/{}?charset=utf8".format \
        (DIALECT, DRIVER, USERNAME, PASSWORD, HOST, PORT, DATABASE)
# 设置每次请求结束后会自动提交数据库中的改动
SQLALCHEMY_COMMIT_ON_TEARDOWN = False
SQLALCHEMY_TRACK_MODIFICATIONS = True
# 查询时会显示原始SQL语句
SQLALCHEMY_ECHO = False

# --------------------------SQL注入检测相关参数--------------------------------
# SQLMAPAPI_FILE_PATH = os.path.dirname(__file__)+"/sqlmap-master/sqlmapapi.py"

# --------------------------rabbitMQ相关参数--------------------------------
MQ_HOST = 'localhost'  # 主机名
MQ_USER = 'guest'  # 用户名
MQ_PASSWORD = 'guest'  # 密码
MQ_PORT = 15672  # 端口
VIRTUAL_HOST = '/'
EXCHANGE_NAME = 'test_celery'

CELERY_BROKER_URL = 'amqp://{0}:{1}@{2}:{3}/{4}'.format(MQ_USER, MQ_PASSWORD, MQ_HOST, MQ_PORT, VIRTUAL_HOST)
# CELERY_RESULT_BACKEND =