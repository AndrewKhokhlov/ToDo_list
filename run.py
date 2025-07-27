import os
from app import create_app, db
from app.models import User
from werkzeug.security import generate_password_hash

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)

'''# Добавьте эту команду
@app.cli.command("create-admin")
def create_admin():
    """Создает пользователя-администратора."""
    if User.query.filter_by(username='Tengakuro').first():
        print('Администратор уже существует.')
        return

    admin = User(
        username='Tengakuro',
        password=generate_password_hash('Gendalf999'),
        is_admin=True
    )
    db.session.add(admin)
    db.session.commit()
    print('Администратор успешно создан!')'''