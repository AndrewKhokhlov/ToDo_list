import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# создаём экземпляры расширений
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'main.login'

def create_app():

    app = Flask(__name__, instance_relative_config=True)

    # базовая конфигурация
    app.config.from_mapping(
        SECRET_KEY='supersecretkey',
        SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(app.instance_path, 'todo.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    # создаём папку instance/
    os.makedirs(app.instance_path, exist_ok=True)

    # инициализируем расширения
    db.init_app(app)
    login_manager.init_app(app)

    # импортируем модели и блюпринт
    from .models import User, Task
    from .routes import main

    # для flask-login: как загружать пользователя из сессии
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # регистрируем маршруты
    app.register_blueprint(main)

    # автоматически создаём файл БД и таблицы, если их нет
    with app.app_context():
        db.create_all()

    return app
