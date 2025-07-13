from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, login_manager
from app.models import User, Task
from app.forms import RegisterForm, LoginForm, TaskForm

main = Blueprint('main', __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@main.route('/')
def home():
    return redirect(url_for('main.login'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Пользователь уже существует")
            return redirect(url_for('main.register'))

        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Регистрация успешна!")
        return redirect(url_for('main.login'))

    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        else:
            flash("Неверный логин или пароль")
    return render_template('login.html', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@main.route('/dashboard')
@login_required
def dashboard():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', tasks=tasks)

@main.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = TaskForm()
    if form.validate_on_submit():
        new_task = Task(
            title=form.title.data,
            content=form.content.data,
            user_id=current_user.id
        )
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('main.dashboard'))

    # для GET (или если валидация не прошла) возвращаем шаблон с формой
    return render_template('add.html', form=form)




@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    task = Task.query.get_or_404(id)
    if task.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))

    form = TaskForm(content=task.content)
    if form.validate_on_submit():
        task.content = form.content.data
        db.session.commit()
        return redirect(url_for('main.dashboard'))
    return render_template('edit.html', form=form)

@main.route('/delete/<int:id>')
@login_required
def delete(id):
    task = Task.query.get_or_404(id)
    if task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('main.dashboard'))
