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
from app.forms import RegisterForm, LoginForm, EditProfileForm, ChangePasswordForm, TaskForm


main = Blueprint('main', __name__)

# Flask-Login: загрузка пользователя
@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))

# Админ-панель
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
    # Сортируем задачи для удобства
    done_tasks = Task.query.filter_by(
        user_id=user_id, completed=True
    ).order_by(Task.id.desc()).all()
    todo_tasks = Task.query.filter_by(
        user_id=user_id, completed=False
    ).order_by(Task.id.desc()).all()

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
        email='tengakuro@example.com',
        password=generate_password_hash('Gendalf999'),
        is_admin=True
    )
    db.session.add(admin)
    db.session.commit()
    return 'Admin created!'

#  Публичные страницы
@main.route('/')
def home():
    if current_user.is_authenticated:
        dest = 'main.admin_panel' if current_user.is_admin else 'main.dashboard'
        return redirect(url_for(dest))
    return redirect(url_for('main.login'))

#  Регистрация / Логин / Логаут
@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    
    form = RegisterForm()
    if form.validate_on_submit():

        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data)
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Регистрация успешна!", 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html', form=form)


@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        # Проверяем, найден ли пользователь и совпадает ли пароль
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Вы успешно вошли в систему!", 'success')
            return redirect(url_for('main.home'))
        
        # Если пользователь не найден или пароль не совпал
        flash("Неверный Email или пароль", 'danger')
    
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
    status = request.args.get('status')
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
        abort(403)

    form = TaskForm(obj=task) # Заполняем форму данными из задачи
    if form.validate_on_submit():
        task.title = form.title.data
        task.content = form.content.data
        db.session.commit()
        return redirect(url_for('main.dashboard'))

    return render_template('edit.html', form=form, task=task)

@main.route('/delete/<int:id>')
@login_required
def delete(id: int):
    task = Task.query.get_or_404(id)
    if task.user_id != current_user.id:
        abort(403)
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

    # Возвращаемся на ту же страницу, с которой пришли
    return redirect(request.referrer or url_for('main.dashboard'))

@main.route('/admin/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_task(task_id):
    """Редактирование задачи от имени администратора."""
    if not current_user.is_admin:
        abort(403)

    task = Task.query.get_or_404(task_id)

    form = TaskForm(obj=task)

    if form.validate_on_submit():
        # Обновляем задачу данными из формы
        task.title = form.title.data
        task.content = form.content.data
        # Если в TaskForm есть поле 'completed', можно обновлять и его
        if 'completed' in form:
            task.completed = form.completed.data
        db.session.commit()
        flash("Задача обновлена", "success")
        return redirect(url_for('main.user_tasks', user_id=task.user_id))
    
    return render_template('edit.html', form=form, task=task)

@main.route('/admin/delete_task/<int:task_id>', methods=['POST'])
@login_required
def admin_delete_task(task_id):
    """Удаление задачи от имени администратора."""
    if not current_user.is_admin:
        abort(403)

    task = Task.query.get_or_404(task_id)
    user_id = task.user_id
    db.session.delete(task)
    db.session.commit()
    flash("Задача удалена", "success")
    return redirect(url_for('main.user_tasks', user_id=user_id))

@main.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Удаление пользователя и ВСЕХ его задач."""
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash("Нельзя удалить другого администратора.", "danger")
        return redirect(url_for('main.admin_panel'))
    
    db.session.delete(user)
    db.session.commit()
    flash(f"Пользователь {user.username} и все его задачи были удалены.", "success")
    return redirect(url_for('main.admin_panel'))


@main.route('/settings', methods=['GET', 'POST'])
@login_required # Только авторизованные пользователи могут получить доступ
def settings():
    form = EditProfileForm(current_user.username, current_user.email) # Передаем текущие данные для валидации
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Ваши настройки профиля были сохранены.', 'success')
        return redirect(url_for('main.settings'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('settings.html', form=form)

@main.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not check_password_hash(current_user.password, form.current_password.data):
            flash('Неверный текущий пароль.', 'danger')
        else:
            current_user.password = generate_password_hash(form.new_password.data)
            db.session.commit()
            flash('Ваш пароль успешно изменен.', 'success')
            return redirect(url_for('main.settings')) # Перенаправляем обратно на страницу настроек
    return render_template('change_password.html', form=form)

@main.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    # 1. Сохраняем ссылку на реальный объект пользователя
    # current_user здесь все еще ссылается на объект User из БД
    user_to_delete = current_user
    
    # 2. Удаляем пользователя из сессии SQLAlchemy
    db.session.delete(user_to_delete)
    db.session.commit() # Зафиксировать удаление в базе данных

    # 3. После успешного удаления из БД, выходим из системы
    logout_user() 
    
    flash('Ваш аккаунт был успешно удален.', 'info')
    return redirect(url_for('main.register')) # Или куда-либо еще после удаления