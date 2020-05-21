from flask_script import Manager
# 从主程序中导入flask实例app
from app import app
# 导入数据库迁移扩展
from flask_migrate import Migrate, MigrateCommand
# 导入SQLAlchemy实例db
from exts import db
# 从数据表的模板文件中导入数据表模型
from models import User, Tasks

manager = Manager(app)

# --------------------------数据库迁移操作-------------------------------
# 数据库初始化执行初始化命令(只需执行一次)
# 初始化迁移环境：python manager.py db init
# 数据库迁移命令执行顺序：每次更改模型之后需执行以下两条命令
# 2.生成迁移文件：python manager.py db migrate
# 3.根据迁移文件映射表：python manager.py db upgrade

# migrate命令实现
# 1.绑定app和db
migrate = Migrate(app, db)

# 2.将MigrateCommand命令添加到manager中
manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    manager.run()
