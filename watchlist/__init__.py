
from flask import Flask

from flask_login import  current_user,  LoginManager

from flask_bootstrap import Bootstrap5

from flask_sqlalchemy import SQLAlchemy
import os

import sys

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://huangzhan:graph@115.157.197.84:3306/LLM'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 关闭对模型修改的监控
db = SQLAlchemy(app)
login_manager = LoginManager(app)  # 实例化扩展类
login_manager.login_view = 'login'
bootstrap = Bootstrap5(app)
LLM_API_URL = 'http://localhost:19327/v1/chat/completions'

@login_manager.user_loader
def load_user(user_email):  # 创建用户加载回调函数，接受用户 ID 作为参数
    from watchlist.models import User
    user = User.query.get(user_email)  # 用 ID 作为 User 模型的主键查询对应的用户
    return user  # 返回用户对象


@app.context_processor
def inject_user():
    # 返回一个包含当前用户信息的字典，如果用户未登录，则返回空字典
    return {"current_user": current_user}
from watchlist import views