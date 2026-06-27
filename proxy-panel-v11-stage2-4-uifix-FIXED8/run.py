"""
Entry point for ProxyPanel.
Usage:
  python run.py                  # production (via gunicorn/systemd)
  python run.py --create-admin   # create/reset admin user
  python run.py --scheduler      # run background scheduler (used by systemd unit)
  python run.py --dev            # flask dev server
"""
import sys
import os

from app import create_app
from app.models import db, User


def create_admin(app):
    with app.app_context():
        username = input("Имя пользователя [admin]: ").strip() or "admin"
        import getpass
        password = getpass.getpass("Пароль: ")
        if not password:
            print("Пароль не может быть пустым")
            sys.exit(1)

        existing = User.query.filter_by(username=username).first()
        if existing:
            existing.set_password(password)
            print(f"Пароль для '{username}' обновлён")
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            print(f"Пользователь '{username}' создан")
        db.session.commit()


app = create_app()

if __name__ == "__main__":
    if "--create-admin" in sys.argv:
        create_admin(app)
    elif "--scheduler" in sys.argv:
        from app.core.scheduler import run_blocking
        run_blocking(app)
    elif "--dev" in sys.argv:
        app.run(host="127.0.0.1", port=5000, debug=True)
    else:
        # gunicorn calls: gunicorn "run:app"
        print("Используйте: gunicorn 'run:app' или python run.py --dev")
