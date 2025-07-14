from flask import (
    Blueprint, abort, render_template, redirect,
    url_for, flash, request
)
from flask_login import (
    login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)

from app import db, login_manager
from app.models import User, Task
from app.forms import RegisterForm, LoginForm, TaskForm

main = Blueprint('main', __name__)

#  Flask‑Login: загрузка пользователя
@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))

#  ⛩  Админ‑панель
@main.route('/admin')
@login_required
def admin_panel():
    """Список всех пользователей (видит только админ)."""
    if not current_user.is_admin:
        abort(403)

    users = User.query.order_by(User.id).all()
    return render_template('admin.html', users=users)


@main.route('/user/<int:user_id>/tasks')
@login_required
def user_tasks(user_id: int):
    """Все задачи конкретного пользователя (доступно только админу)."""
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    done_tasks = Task.query.filter_by(
        user_id=user_id, completed=True
    ).all()
    todo_tasks = Task.query.filter_by(
        user_id=user_id, completed=False
    ).all()

    return render_template(
        'user_tasks.html',
        user=user,
        done_tasks=done_tasks,
        todo_tasks=todo_tasks
    )

# Временный роут для первого создания админа.
@main.route('/create-admin')
def create_admin():
    """Однократное создание суперпользователя."""
    if User.query.filter_by(username='Tengakuro').first():
        return 'Admin already exists'

    admin = User(
        username='Tengakuro',
        password=generate_password_hash('Gendalf999'),
        is_admin=True
    )
    db.session.add(admin)
    db.session.commit()
    return 'Admin created!'

#  Публичные страницы
@main.route('/')
def home():
    return redirect(url_for('main.login'))

#  Регистрация / Логин / Логаут
@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Пользователь уже существует")
            return redirect(url_for('main.register'))

        new_user = User(
            username=form.username.data,
            password=generate_password_hash(form.password.data)
        )
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

            # Админ → /admin, обычный юзер → /dashboard
            dest = 'main.admin_panel' if user.is_admin else 'main.dashboard'
            return redirect(url_for(dest))

        flash("Неверный логин или пароль")

    return render_template('login.html', form=form)


@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

#  Задачи текущего пользователя
@main.route('/dashboard')
@login_required
def dashboard():
    status = request.args.get('status')  # "completed", "active", None
    query = Task.query.filter_by(user_id=current_user.id)

    if status == 'completed':
        query = query.filter_by(completed=True)
    elif status == 'active':
        query = query.filter_by(completed=False)

    tasks = query.order_by(Task.id.desc()).all()
    return render_template(
        'dashboard.html',
        tasks=tasks,
        status=status
    )

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

    return render_template('add.html', form=form)

@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id: int):
    task = Task.query.get_or_404(id)
    if task.user_id != current_user.id:
        return redirect(url_for('main.dashboard'))

    form = TaskForm(title=task.title, content=task.content)
    if form.validate_on_submit():
        task.title = form.title.data
        task.content = form.content.data
        db.session.commit()
        return redirect(url_for('main.dashboard'))

    return render_template('edit.html', form=form)

@main.route('/delete/<int:id>')
@login_required
def delete(id: int):
    task = Task.query.get_or_404(id)
    if task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('main.dashboard'))

@main.route('/toggle/<int:id>', methods=['POST'])
@login_required
def toggle_status(id: int):
    task = Task.query.get_or_404(id)
    if task.user_id != current_user.id:
        abort(403)

    task.completed = not task.completed
    db.session.commit()

    status = request.args.get('status')
    return redirect(
        url_for('main.dashboard', status=status)
        if status else url_for('main.dashboard')
    )
