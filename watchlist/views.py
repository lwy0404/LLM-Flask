from datetime import datetime

import requests
from flask_wtf import FlaskForm
from sqlalchemy.exc import SQLAlchemyError

from watchlist import app, db, LLM_API_URL
from watchlist.models import User, Schedule
from flask_login import login_user, login_required, logout_user, current_user
from flask import render_template, request, url_for, redirect, flash
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from flask_wtf import FlaskForm


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
        DataRequired(message=u'日程信息不能为空'), Length(1, 1024)])
    submit = SubmitField(u'解析')


class submit_to_MySQL(FlaskForm):
    event = StringField(u'事件', validators=[
        DataRequired(message=u'事件不能为空'), Length(1, 1024)])
    date = StringField(u'日程', validators=[
        DataRequired(message=u'日期不能为空'),
        Regexp(r'^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}$', message=u'日期格式必须为YYYY-MM-DD HH:MM')
    ])
    location = StringField(u'地点')


class delete_event(FlaskForm):
    delete = SubmitField('Delete')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        useremail = form.email.data
        password = form.password.data
        user = User.query.get(useremail)
        if user is not None and user.validate_password(password):
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
        return redirect(url_for('login'))

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


@app.route('/addSchedule_LLM', methods=['GET', 'POST'])
def addSchedule_LLM():
    form_llm = submit_to_LLMForm()
    form_mysql = submit_to_MySQL()
    if request.method == 'POST' and form_llm.validate_on_submit():
        # Get the input from the submit_to_LLMForm
        user_message = "我需要你从日程信息中提取出时间,地点和事件.输出格式为时间:....;地点:....;事件:.....;除此之外不能有多余的输出.日程信息:" + form_llm.events.data

        # Prepare the payload for the LLM API request
        payload = {
            "messages": [{"role": "user", "message": user_message}],
            "repetition_penalty": 1.0
        }
        # Make the request to the LLM API
        response = requests.post(LLM_API_URL, json=payload)

        if response.status_code == 200:
            data = response.json()
            choices_list = data.get("choices", [])
            if len(choices_list) >= 2:
                extracted_data = choices_list[1].get("message", {}).get("content", "")
            # Process the response to extract the relevant information

            '''flash("data from API:" + extracted_data)'''
            # Split the extracted_data to get the time, location, and event
            extracted_data = extracted_data.split(';')

            time = extracted_data[0].split(':')[1].strip()
            location = extracted_data[1].split(':')[1].strip()
            event = extracted_data[2].split(':')[1].strip()


            # Populate the submit_to_MySQL form with the extracted data
            form_mysql.event.data = event
            flash("event from API:" + form_mysql.event.data)
            form_mysql.date.data = time
            form_mysql.location.data = location

    elif request.method == 'POST' and form_mysql.validate_on_submit():
        try:
            sc_time = datetime.strptime(form_mysql.date.data, "%Y-%m-%d %H:%M")  # 添加分钟部分的格式化选项
            schedule = Schedule(date=sc_time,
                                    scheduleEvent=form_mysql.event.data,  # 将event字段赋给scheduleEvent
                                    location=form_mysql.location.data,
                                    user_email=current_user.email)
            db.session.add(schedule)
            db.session.commit()
            flash('Schedule information added successfully.')
        except ValueError as e:
            flash(f'Error parsing date: {e}', 'danger')
        except SQLAlchemyError as e:
            db.session.rollback()
            error_msg = str(e)
            flash(f'Error adding schedule information: {error_msg}', 'danger')
        return redirect(url_for('addSchedule_LLM'))
    elif request.method == 'POST' and form_mysql.validate_on_submit() is False :
        if bool(form_mysql.event.errors):
            flash("event_errors: " + ", ".join(form_mysql.event.errors))
        if bool(form_mysql.date.errors):
            flash("date_errors: " + ", ".join(form_mysql.date.errors))
        if bool(form_mysql.location.errors):
            flash("location_errors: " + ", ".join(form_mysql.location.errors))
        return redirect(url_for('addSchedule_LLM'))
    return render_template('addSchedule.html', form_llm=form_llm, form_mysql=form_mysql)





@app.route('/viewSchedule', methods=['GET', 'POST'])
def viewSchedule():
    form = delete_event()
    page = int(request.args.get('page', 1))  # 获取页码，默认为第一页
    per_page = 10  # 每页显示的日程数量
    user_schedules = Schedule.query.filter_by(user_email=current_user.email).order_by(Schedule.date.desc()).paginate(
        page, per_page, error_out=False)

    return render_template('viewSchedule.html', user_schedules=user_schedules, form=form)


@app.route('/viewSchedule/delete/<string:event_date>', methods=['POST'])  # 限定只接受 POST 请求
def delete(event_date):
    event_date = datetime.strptime(event_date, "%Y-%m-%d %H:%M:%S")
    try:
        event = Schedule.query.filter_by(user_email=current_user.email, date=event_date).first()
        if not event:
            raise Exception("Event not found")  # 抛出异常，提示未找到对应的记录

        db.session.delete(event)  # 删除对应的记录
        db.session.commit()  # 提交数据库会话
        flash('Item deleted.')
    except Exception as e:
        db.session.rollback()  # 出现异常时回滚数据库会话
        flash('Error deleting item: {}'.format(str(e)))  # 显示错误消息

    return redirect(url_for('viewSchedule'))  # 重定向回主页
