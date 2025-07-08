import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# 1) Создаём глобальные экземпляры расширений
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'main.login'

def create_app():
    # 2) Flask узнаёт, что есть папка instance рядом с проектом:
    #    — Flask автоматически создаст instance/ рядом с run.py
    app = Flask(
        __name__,
        instance_relative_config=True,
        static_folder=os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'static'),
        static_url_path='/static'
    )

    # 3) Убеждаемся, что папка instance существует
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # 4) Конфигурация базы
    #    sqlite:///<абсолютный путь до instance/todo.db>
    db_path = os.path.join(app.instance_path, 'todo.db')
    app.config['SECRET_KEY'] = 'supersecretkey'
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # 5) Инициализируем расширения
    db.init_app(app)
    login_manager.init_app(app)

    # 6) Регистрируем Blueprint’ы
    from app.routes import main
    app.register_blueprint(main)

    return app
