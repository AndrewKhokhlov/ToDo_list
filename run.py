from app import create_app, db

app = create_app()

# Авто‑создание таблиц при каждом запуске (если их ещё нет)
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))