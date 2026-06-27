"""Page views blueprint."""
from flask import Blueprint, render_template, redirect, url_for, request
from flask_login import login_required
from app.models import Setting

bp = Blueprint("views", __name__)


@bp.get("/")
def index():
    return redirect(url_for("views.dashboard"))


@bp.get("/setup-progress")
@login_required
def setup_progress():
    domain = Setting.get("panel_domain", "")
    return render_template("pages/setup_progress.html", domain=domain)


@bp.get("/dashboard")
@login_required
def dashboard():
    if not Setting.get("panel_domain"):
        return redirect(url_for("views.setup"))
    return render_template("pages/dashboard.html")


@bp.get("/setup")
@login_required
def setup():
    return render_template("pages/setup.html")


@bp.post("/setup")
@login_required
def setup_post():
    """No-JS fallback. В текущем UI форма submit'ится через JS на
    /api/system/enable-https — этот обработчик нужен только если
    JavaScript отключён в браузере.
    """
    from app.api.system import _do_https_setup
    panel_domain = request.form.get("panel_domain", "").strip()
    acme_email   = request.form.get("acme_email", "").strip()
    # Пользователь подтвердил продолжить, несмотря на DNS-предупреждение
    force        = request.form.get("force") == "1"

    if not panel_domain:
        return render_template("pages/setup.html", error="Домен панели обязателен",
                               panel_domain=panel_domain, acme_email=acme_email)

    ok, msg = _do_https_setup(panel_domain, acme_email, force=force)

    if not ok and msg == "dns_warning":
        # Показываем форму с предупреждением + скрытым input force=1, чтобы
        # повторный submit прошёл через force-ветку. Раньше тут стояло force=True
        # безусловно — это сжигало rate-limit Let's Encrypt, когда DNS не настроен.
        return render_template("pages/setup.html",
                               warning="Домен пока не указывает на этот сервер. "
                                       "Сертификат может не выпуститься. Продолжить?",
                               show_force=True,
                               panel_domain=panel_domain, acme_email=acme_email)

    if not ok:
        return render_template("pages/setup.html", error=msg,
                               panel_domain=panel_domain, acme_email=acme_email)

    return redirect(url_for("views.setup_progress"))


@bp.get("/inbounds")
@login_required
def inbounds():
    return render_template("pages/inbounds.html")


@bp.get("/clients/<int:ib_id>")
@login_required
def clients(ib_id):
    return render_template("pages/clients.html", inbound_id=ib_id)


@bp.get("/routing")
@login_required
def routing():
    return render_template("pages/routing.html")


@bp.get("/security")
@login_required
def security():
    return render_template("pages/security.html")


@bp.get("/split-tunnel")
@login_required
def split_tunnel():
    return render_template("pages/split_tunnel.html")


@bp.get("/server")
@login_required
def server():
    return render_template("pages/server.html")


# Старые URL /system и /settings — теперь редиректы на /server.
# Сохраняем их, чтобы не ломать сохранённые ссылки и закладки.
@bp.get("/system")
@login_required
def system():
    return redirect(url_for("views.server"))


@bp.get("/settings")
@login_required
def settings():
    return redirect(url_for("views.server"))
