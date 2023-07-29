import requests
from datetime import datetime
from flask import Flask, render_template, request, flash, redirect, url_for
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user, UserMixin, LoginManager
from wtforms import StringField, SubmitField, PasswordField, DateTimeField
from wtforms.validators import DataRequired, Length, Email, ValidationError, EqualTo, Regexp
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap5
import email_validator
import flask_mysqldb
from flask_sqlalchemy import SQLAlchemy
from markupsafe import escape
import os
import click
import sys

app = Flask(__name__)
app.secret_key = 'Liwanyun888'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Liwanyun888@localhost:3306/watchlist'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 关闭对模型修改的监控
db = SQLAlchemy(app)
login_manager = LoginManager(app)  # 实例化扩展类
login_manager.login_view = 'login'
bootstrap = Bootstrap5(app)
LLM_API_URL = 'http://115.157.198.84:19327/v1/chat/completions'


class User(db.Model, UserMixin):
    email = db.Column(db.String(30), primary_key=True)
    password_hash = db.Column(db.String(128))  # 密码散列值
    schedule = db.relationship('Schedule', backref='user', lazy=True)

    def set_password(self, password):  # 用来设置密码的方法，接受密码作为参数
        self.password_hash = generate_password_hash(password)  # 将生成的密码保持到对应字段

    def validate_password(self, password):  # 用于验证密码的方法，接受密码作为参数
        return check_password_hash(self.password_hash, password)  # 返回布尔值


class Schedule(db.Model):
    date = db.Column(db.DateTime, primary_key=True)
    scheduleEvent = db.Column(db.Text)
    location = db.Column(db.Text)
    user_email = db.Column(db.String(30), db.ForeignKey('user.email'),
                           nullable=False,primary_key=True)


class LoginForm(FlaskForm):
    email = StringField(u'邮箱', validators=[
        DataRequired(message=u'邮箱不能为空'), Length(1, 64),
        Email(message=u'请输入有效的邮箱地址，比如：username@domain.com')])
    password = PasswordField(u'密码',
                             validators=[DataRequired(message=u'密码不能为空')])
    submit = SubmitField(u'登录')


class RegisterForm(FlaskForm):
    email = StringField(u'邮箱', validators=[
        DataRequired(message=u'邮箱不能为空'), Length(1, 64),
        Email(message=u'请输入有效的邮箱地址，比如：username@domain.com')])
    password = PasswordField(u'密码',
                             validators=[DataRequired(message=u'密码不能为空')])
    repeatPassword = PasswordField('确认密码', validators=[
        DataRequired(message='确认密码不能为空'),
        EqualTo('password', message='两次输入的密码不一致')])
    submit = SubmitField(u'注册')


class submit_to_LLMForm(FlaskForm):
    events = StringField(u'日程', validators=[
        DataRequired(message=u'日程信息不能为空'), Length(1, 64)])
    submit = SubmitField(u'解析')


class submit_to_MySQL(FlaskForm):
    event = StringField(u'事件', validators=[
        DataRequired(message=u'事件不能为空'), Length(1, 64)])
    date = StringField(u'日程',validators=[
        DataRequired(message=u'日期不能为空'),
        Regexp(r'^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}$', message=u'日期格式必须为YYYY-MM-DD HH:MM')
    ])
    location = StringField(u'地点')


@login_manager.user_loader
def load_user(user_email):  # 创建用户加载回调函数，接受用户 ID 作为参数
    user = User.query.get(user_email)  # 用 ID 作为 User 模型的主键查询对应的用户
    return user  # 返回用户对象


@app.context_processor
def inject_user():
    # 返回一个包含当前用户信息的字典，如果用户未登录，则返回空字典
    return {"current_user": current_user}


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        useremail = form.email.data
        password = form.password.data
        user = User.query.get(useremail)
        if useremail == user.email and user.validate_password(password):
            login_user(user)  # 登入用户
            flash('Login success.')
            return render_template('index.html')

        flash('Invalid username or password.')  # 如果验证失败，显示错误消息
        return redirect(url_for('login'))  # 重定向回登录页面

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        useremail = form.email.data
        password = form.password.data

        if User.query.filter_by(email=useremail).first():
            flash('该邮箱已被注册，请换一个。', 'danger')
            return redirect(url_for('register'))

        user = User(email=useremail)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('register success. Please log in')
        newForm = LoginForm()
        return render_template('login.html', form=newForm)

    return render_template('register.html', form=form)


@app.route('/logout')
@login_required  # 视图保护
def logout():
    logout_user()  # 登出用户
    flash('Goodbye.')
    return redirect(url_for('beginpage'))  # 重定向回首页


@app.route('/', methods=['GET'])
def beginpage():
    return render_template('beginpage.html')


@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/addSchedule', methods=['GET', 'POST'])
def addSchedule():
    form_llm = submit_to_LLMForm()
    form_mysql = submit_to_MySQL()

    if request.method == 'POST' and form_llm.validate_on_submit():
        # Get the input from the submit_to_LLMForm
        user_message = form_llm.events.data

        # Prepare the payload for the LLM API request
        payload = {
            "messages": [{"role": "user", "message": user_message}],
            "repetition_penalty": 1.0
        }

        # Make the request to the LLM API
        response = requests.post(LLM_API_URL, json=payload)
        data = response.json()

        # Process the response to extract the relevant information
        extracted_data = data.get("choices", [{}])[0].get("message", {}).get("content", "")

        # Split the extracted_data to get the time, location, and event
        extracted_data = extracted_data.split(';')
        time = extracted_data[0].split(':')[1].strip()
        location = extracted_data[1].split(':')[1].strip()
        event = extracted_data[2].split(':')[1].strip()

        # Populate the submit_to_MySQL form with the extracted data
        form_mysql.event.data = event
        form_mysql.date.data = time
        form_mysql.location.data = location

        if form_mysql.validate_on_submit():
            try:
                sc_time = datetime.strptime(form_mysql.date.data, "%Y-%m-%d %H:%M")  # 添加分钟部分的格式化选项
                schedule = Schedule(date=form_mysql.date.data,
                                    scheduleEvent=form_mysql.event.data,  # 将event字段赋给scheduleEvent
                                    location=form_mysql.location.data)
                db.session.add(schedule)
                db.session.commit()
                flash('Schedule information added successfully.')
            except ValueError as e:
                flash(f'Error parsing date: {e}', 'danger')
            except SQLAlchemyError as e:
                db.session.rollback()
                error_msg = str(e)
                flash(f'Error adding schedule information: {error_msg}', 'danger')
    return render_template('addSchedule.html', form_llm=form_llm, form_mysql=form_mysql)


@app.route('/viewSchedule', methods=['GET', 'POST'])
def viewSchedule():
    return render_template('beginpage.html')
