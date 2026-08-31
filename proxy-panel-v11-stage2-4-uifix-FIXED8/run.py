"""
Entry point for ProxyPanel.
Usage:
  python run.py                  # production (via gunicorn/systemd)
  python run.py --create-admin   # create/reset admin (non-interactive)
                                 #   --username X --password Y, либо env
                                 #   PP_ADMIN_USERNAME / PP_ADMIN_PASSWORD;
                                 #   без пароля в терминале — спросит getpass,
                                 #   без терминала — сгенерирует и напечатает.
  python run.py --scheduler      # run background scheduler (used by systemd unit)
  python run.py --dev            # flask dev server
"""
import sys
import os

from app import create_app
from app.models import db, User


def _argval(flag: str):
    """Значение флага `--flag value` из argv, иначе None."""
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


def create_admin(app):
    """Создать (или сбросить пароль) администратора.

    НЕИНТЕРАКТИВНО ПО УМОЛЧАНИЮ. Раньше здесь были input()+getpass(), и это
    ломало установку: через `curl … | sudo bash` и `su -c` стандартный ввод —
    не терминал, приглашение проскакивало (пользователь оставался без входа),
    а getpass не мог погасить эхо и печатал пароль на экран. Теперь источники,
    по приоритету:
      1. флаги `--username` / `--password`;
      2. переменные окружения PP_ADMIN_USERNAME / PP_ADMIN_PASSWORD
         (их передаёт install.sh);
      3. если пароль так и не задан:
         • есть реальный терминал → спрашиваем через getpass (ручной запуск);
         • нет терминала → генерируем стойкий пароль и ПЕЧАТАЕМ его
           (машиночитаемой строкой, install.sh покажет её в финале).
    Тот же вызов сбрасывает пароль существующему администратору.
    """
    import getpass
    import secrets
    import string

    username = (
        _argval("--username") or os.environ.get("PP_ADMIN_USERNAME") or ""
    ).strip()
    password = _argval("--password") or os.environ.get("PP_ADMIN_PASSWORD")
    interactive = sys.stdin.isatty()

    if not username:
        username = (
            (input("Имя пользователя [admin]: ").strip() or "admin")
            if interactive
            else "admin"
        )

    generated = False
    if not password:
        if interactive:
            password = getpass.getpass("Пароль: ")
            if not password:
                print("Пароль не может быть пустым")
                sys.exit(1)
        else:
            # Алфавит без спецсимволов оболочки — пароль безопасно пробрасывать
            # через env в `su -c` без экранирования (см. install.sh, шаг 9).
            alphabet = string.ascii_letters + string.digits
            password = "".join(secrets.choice(alphabet) for _ in range(16))
            generated = True

    with app.app_context():
        existing = User.query.filter_by(username=username).first()
        if existing:
            existing.set_password(password)
            action = "обновлён"
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            action = "создан"
        db.session.commit()

    if generated:
        # Машиночитаемая строка для install.sh (он её поймает и покажет в
        # финальном блоке). Пароль виден ОДИН раз — дальше его знает владелец.
        print(f"PP_ADMIN_CREDENTIALS username={username} password={password}")
    print(f"Администратор '{username}' {action}.")


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
