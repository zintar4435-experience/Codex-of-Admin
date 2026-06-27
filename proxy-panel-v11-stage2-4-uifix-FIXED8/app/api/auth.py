"""Auth blueprint — login/logout."""
from flask import Blueprint, request, jsonify, redirect, url_for, render_template, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.models import db, User
from app.core.audit import log_action
from app import limiter

bp = Blueprint("auth", __name__)


@bp.get("/login")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("views.dashboard"))
    return render_template("pages/login.html")


@bp.post("/login")
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "").strip()
    password = data.get("password", "")
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        # Залогируем провалившуюся попытку — username берём из формы (не из current_user),
        # передаём явно, чтобы аудит видел, КОГО ПЫТАЛИСЬ авторизовать.
        log_action("auth.login_failed", username=username or "(empty)",
                   details={"reason": "bad_credentials"})
        if request.is_json:
            return jsonify({"error": "Неверные учётные данные"}), 401
        flash("Неверный логин или пароль", "danger")
        return redirect(url_for("auth.login_page"))

    # Второй фактор: если у пользователя включён TOTP — требуем код.
    if user.totp_enabled:
        code = (data.get("code", "") or "").strip()
        if not code:
            # Пароль верный, но нужен код — сообщаем фронту показать поле кода.
            if request.is_json:
                return jsonify({"error": "Требуется код двухфакторной аутентификации",
                                "twofa_required": True}), 401
            flash("Введите код двухфакторной аутентификации", "warning")
            return redirect(url_for("auth.login_page"))
        from app.core import totp
        ok = totp.verify(user.totp_secret, code)
        if not ok and user.use_recovery_code(code):
            ok = True
            db.session.commit()
            log_action("auth.recovery_code_used", username=user.username,
                       details={"left": user.recovery_codes_left()})
        if not ok:
            log_action("auth.login_failed", username=username, details={"reason": "bad_2fa"})
            if request.is_json:
                return jsonify({"error": "Неверный код", "twofa_required": True}), 401
            flash("Неверный код двухфакторной аутентификации", "danger")
            return redirect(url_for("auth.login_page"))

    login_user(user)
    log_action("auth.login", username=user.username)
    if request.is_json:
        return jsonify({"ok": True})
    return redirect(url_for("views.dashboard"))


@bp.get("/onboarding-handoff")
@limiter.limit("20 per minute")
def onboarding_handoff():
    """One-shot вход по handoff-токену для перехода админа с http://IP:5000
    на https://panel_domain/ после выпуска TLS-сертификата.

    Токен выписывается /api/system/onboarding-handoff на HTTP origin'е
    (где у юзера действующая сессия), и сразу же редиректом подставляется
    в этот эндпоинт на HTTPS origin'е. Токен одноразовый, TTL — 60 секунд.

    После успешного логина планируем рестарт самой панели (отложенный,
    чтобы успел улететь HTTP-редирект): после рестарта новый gunicorn
    подхватит HTTPS_ENABLED=true и включит ProxyFix middleware.
    """
    from app.api.system import consume_handoff_token, schedule_panel_restart

    token = request.args.get("token", "")
    user_id = consume_handoff_token(token)
    if user_id is None:
        flash("Сессия онбординга устарела или ссылка уже использована. "
              "Войдите заново.", "warning")
        return redirect(url_for("auth.login_page"))

    user = db.session.get(User, user_id)
    if user is None:
        flash("Учётная запись не найдена. Войдите заново.", "warning")
        return redirect(url_for("auth.login_page"))

    login_user(user)
    log_action("auth.onboarding_handoff", username=user.username)

    # Запланировать рестарт панели на 3 секунды позже — успеют:
    #  1) Flask вернуть 302 на /dashboard,
    #  2) браузер сходить за /dashboard,
    #  3) и только потом gunicorn рестартанётся с HTTPS_ENABLED=true.
    schedule_panel_restart(delay_seconds=3)

    return redirect(url_for("views.dashboard"))


@bp.post("/logout")
@login_required
def logout():
    # Запоминаем юзера ДО logout — после logout_user current_user уже anonymous.
    uname = current_user.username
    logout_user()
    log_action("auth.logout", username=uname)
    return redirect(url_for("auth.login_page"))
