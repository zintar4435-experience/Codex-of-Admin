"""
SQLAlchemy models for Proxy Panel.
"""
import uuid
import json
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


def generate_uuid():
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Users (panel admins)
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # --- Двухфакторная аутентификация (TOTP) ---
    totp_secret = db.Column(db.String(64), nullable=True)        # Base32; при setup хранится как «ожидающий», enabled=False
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    recovery_codes = db.Column(db.Text, nullable=True)           # JSON-список хешей одноразовых кодов

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def set_recovery_codes(self, codes):
        """Сохранить резервные коды (храним только хеши)."""
        import json
        self.recovery_codes = json.dumps([
            generate_password_hash(c, method="pbkdf2:sha256") for c in codes
        ])

    def use_recovery_code(self, code: str) -> bool:
        """Проверить и «потратить» резервный код. True — если подошёл."""
        import json
        if not self.recovery_codes:
            return False
        code = (code or "").strip().lower()
        try:
            hashes = json.loads(self.recovery_codes)
        except (ValueError, TypeError):
            return False
        for h in hashes:
            if check_password_hash(h, code):
                hashes.remove(h)
            else:
                continue
            self.recovery_codes = json.dumps(hashes)
            return True
        return False

    def recovery_codes_left(self) -> int:
        import json
        if not self.recovery_codes:
            return 0
        try:
            return len(json.loads(self.recovery_codes))
        except (ValueError, TypeError):
            return 0

    def to_dict(self):
        return {"id": self.id, "username": self.username, "created_at": self.created_at.isoformat()}


# ---------------------------------------------------------------------------
# Inbounds
# ---------------------------------------------------------------------------

class Inbound(db.Model):
    __tablename__ = "inbounds"

    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String(64), unique=True, nullable=False)   # unique xray tag / caddy site name
    engine = db.Column(db.String(16), nullable=False)             # "xray" | "naive"
    protocol = db.Column(db.String(32), nullable=False)           # vmess/vless/trojan/ss/socks/http/dokodemo/naive
    port = db.Column(db.Integer, nullable=True)                   # None for NaiveProxy (always 443)
    domain = db.Column(db.String(256), nullable=True)             # required for NaiveProxy & TLS
    tls_enabled = db.Column(db.Boolean, default=False)
    tls_cert_path = db.Column(db.String(512), nullable=True)
    tls_key_path = db.Column(db.String(512), nullable=True)
    tls_acme = db.Column(db.Boolean, default=False)               # auto Let's Encrypt
    transport = db.Column(db.String(32), nullable=True)           # tcp/ws/grpc/kcp/h2 (Xray only)
    transport_config = db.Column(db.Text, default="{}")           # JSON: path, host, etc.
    probe_resistance_secret = db.Column(db.String(256), nullable=True)  # NaiveProxy probe_resistance URL
    extra_config = db.Column(db.Text, default="{}")               # protocol-specific JSON blob
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    clients = db.relationship("Client", back_populates="inbound", cascade="all, delete-orphan")
    routing_rules_src = db.relationship(
        "RoutingRule", foreign_keys="RoutingRule.src_inbound_id",
        back_populates="src_inbound", cascade="all, delete-orphan"
    )
    routing_rules_dst = db.relationship(
        "RoutingRule", foreign_keys="RoutingRule.dst_inbound_id",
        back_populates="dst_inbound"
    )

    def get_transport_config(self) -> dict:
        return json.loads(self.transport_config or "{}")

    def get_extra_config(self) -> dict:
        return json.loads(self.extra_config or "{}")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tag": self.tag,
            "engine": self.engine,
            "protocol": self.protocol,
            "port": self.port,
            "domain": self.domain,
            "tls_enabled": self.tls_enabled,
            "tls_acme": self.tls_acme,
            "transport": self.transport,
            "transport_config": self.get_transport_config(),
            # probe_resistance_secret намеренно исключён из общего ответа;
            # доступен только через GET /api/inbounds/<id>/secret
            "extra_config": self.get_extra_config(),
            "enabled": self.enabled,
            "client_count": len(self.clients),
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

class Client(db.Model):
    __tablename__ = "clients"
    __table_args__ = (
        # Защита на уровне БД от дубликатов email/username в одном инбаунде.
        # Xray не допускает двух клиентов с одинаковым email (stats-ключ).
        # Если UI или API каким-то образом пропустили дубликат — SQLite не даст
        # сохранить второй ряд, и handler вернёт IntegrityError → 409.
        db.UniqueConstraint("inbound_id", "email", name="uq_client_inbound_email"),
        db.UniqueConstraint("inbound_id", "username", name="uq_client_inbound_username"),
    )

    id = db.Column(db.Integer, primary_key=True)
    inbound_id = db.Column(db.Integer, db.ForeignKey("inbounds.id"), nullable=False)
    name = db.Column(db.String(128), nullable=False)              # display name / remark
    uuid = db.Column(db.String(36), default=generate_uuid)       # Xray UUID
    password = db.Column(db.String(256), nullable=True)          # Shadowsocks / NaiveProxy
    username = db.Column(db.String(128), nullable=True)          # NaiveProxy login
    email = db.Column(db.String(256), nullable=True)             # used as Xray stats key
    flow = db.Column(db.String(64), nullable=True)               # xtls-rprx-vision etc.

    # Limits
    expire_at = db.Column(db.DateTime, nullable=True)
    traffic_limit_up = db.Column(db.BigInteger, default=0)       # bytes, 0 = unlimited
    traffic_limit_down = db.Column(db.BigInteger, default=0)     # bytes, 0 = unlimited

    # Counters (reset-able)
    traffic_used_up = db.Column(db.BigInteger, default=0)
    traffic_used_down = db.Column(db.BigInteger, default=0)
    traffic_reset_at = db.Column(db.DateTime, nullable=True)

    # "Last seen" значения внешних счётчиков (Xray stats / Caddy access-log sum).
    # Нужны для корректного вычисления дельты: если внешний счётчик упал
    # (рестарт Xray, ротация лога Caddy) — считаем, что это новая эпоха,
    # и берём текущее значение как дельту. Не путать с traffic_used_*:
    # traffic_used_* — это accumulator (используется в UI и для лимитов),
    # last_seen_* — это технический «маркер прошлого тика».
    last_seen_up = db.Column(db.BigInteger, default=0)
    last_seen_down = db.Column(db.BigInteger, default=0)

    # Токен для subscription URL: /sub/<share_token>.
    # Несколько клиентов могут иметь одинаковый share_token — тогда подписка
    # вернёт все их ссылки одним base64-блобом (удобно, когда один человек
    # пользуется несколькими inbound'ами).
    # По умолчанию у каждого клиента свой токен (default=generate_uuid),
    # объединение делается админом вручную через PUT /api/clients/<id>.
    share_token = db.Column(db.String(36), default=generate_uuid, nullable=True, index=True)

    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    inbound = db.relationship("Inbound", back_populates="clients")
    traffic_history = db.relationship("TrafficStat", back_populates="client", cascade="all, delete-orphan")

    @property
    def is_expired(self) -> bool:
        if self.expire_at is None:
            return False
        expire = self.expire_at
        if expire.tzinfo is None:
            expire = expire.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expire

    @property
    def is_over_limit(self) -> bool:
        if self.traffic_limit_up > 0 and self.traffic_used_up >= self.traffic_limit_up:
            return True
        if self.traffic_limit_down > 0 and self.traffic_used_down >= self.traffic_limit_down:
            return True
        return False

    @property
    def is_active(self) -> bool:
        return self.enabled and not self.is_expired and not self.is_over_limit

    def reset_traffic(self):
        # last_seen_* НЕ трогаем: иначе при следующем тике Xray вернёт
        # своё cumulative-значение, и весь старый трафик прибавится повторно.
        # Если бы сейчас был рестарт Xray — _accumulate_delta это поймает
        # через "new < last_seen" и сам обнулит last_seen.
        self.traffic_used_up = 0
        self.traffic_used_down = 0
        self.traffic_reset_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "inbound_id": self.inbound_id,
            "name": self.name,
            "uuid": self.uuid,
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "flow": self.flow,
            "expire_at": self.expire_at.isoformat() if self.expire_at else None,
            "traffic_limit_up": self.traffic_limit_up,
            "traffic_limit_down": self.traffic_limit_down,
            "traffic_used_up": self.traffic_used_up,
            "traffic_used_down": self.traffic_used_down,
            "share_token": self.share_token,
            "is_expired": self.is_expired,
            "is_over_limit": self.is_over_limit,
            "is_active": self.is_active,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# Traffic stats (historical snapshots)
# ---------------------------------------------------------------------------

class TrafficStat(db.Model):
    __tablename__ = "traffic_stats"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    recorded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    delta_up = db.Column(db.BigInteger, default=0)
    delta_down = db.Column(db.BigInteger, default=0)

    client = db.relationship("Client", back_populates="traffic_history")


# ---------------------------------------------------------------------------
# Routing rules (cascade / split-tunnel)
# ---------------------------------------------------------------------------

ROUTING_ACTION_DIRECT = "direct"
ROUTING_ACTION_BLOCK = "block"
ROUTING_ACTION_INBOUND = "inbound"   # forward to another inbound (cascade)
ROUTING_ACTION_OUTBOUND = "outbound" # external SOCKS5/HTTP proxy


class RoutingRule(db.Model):
    __tablename__ = "routing_rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    priority = db.Column(db.Integer, default=100)                # lower = higher priority

    # Source: which inbound this rule applies to (NULL = all)
    src_inbound_id = db.Column(db.Integer, db.ForeignKey("inbounds.id"), nullable=True)

    # Conditions (JSON lists)
    match_domains = db.Column(db.Text, default="[]")             # ["geosite:ru", "domain:vk.com"]
    match_ips = db.Column(db.Text, default="[]")                 # ["geoip:ru", "1.2.3.0/24"]
    match_protocols = db.Column(db.Text, default="[]")           # ["http", "tls"]
    match_ports = db.Column(db.String(256), nullable=True)       # "80,443,8000-9000"
    # match_network: NULL = оба (TCP+UDP, без фильтра); иначе "tcp" или "udp".
    # В Xray-конфиге включается только если значение не NULL.
    match_network = db.Column(db.String(8), nullable=True)

    # Action
    action = db.Column(db.String(16), nullable=False)            # direct/block/inbound/outbound
    dst_inbound_id = db.Column(db.Integer, db.ForeignKey("inbounds.id"), nullable=True)  # if action=inbound
    dst_outbound_tag = db.Column(db.String(64), nullable=True)   # if action=outbound (external proxy tag)

    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    src_inbound = db.relationship(
        "Inbound", foreign_keys=[src_inbound_id], back_populates="routing_rules_src"
    )
    dst_inbound = db.relationship(
        "Inbound", foreign_keys=[dst_inbound_id], back_populates="routing_rules_dst"
    )

    def get_match_domains(self) -> list:
        return json.loads(self.match_domains or "[]")

    def get_match_ips(self) -> list:
        return json.loads(self.match_ips or "[]")

    def get_match_protocols(self) -> list:
        return json.loads(self.match_protocols or "[]")

    def to_dict(self) -> dict:
        # Лениво проверяем geosite:/geoip:-коды через xray. Кэш в
        # модуле geo_validator не даёт делать subprocess на каждое
        # обращение к одному и тому же коду. Fail-open: если
        # валидатор недоступен — список пустой, бейдж не показывается.
        try:
            from app.core.geo_validator import validate_codes
            invalid = validate_codes(self.get_match_domains(), self.get_match_ips())
        except Exception:
            invalid = []
        return {
            "id": self.id,
            "name": self.name,
            "priority": self.priority,
            "src_inbound_id": self.src_inbound_id,
            "match_domains": self.get_match_domains(),
            "match_ips": self.get_match_ips(),
            "match_protocols": self.get_match_protocols(),
            "match_ports": self.match_ports,
            "match_network": self.match_network,
            "action": self.action,
            "dst_inbound_id": self.dst_inbound_id,
            "dst_outbound_tag": self.dst_outbound_tag,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
            # Список исходных строк, которые xray не смог распознать
            # как существующие коды. Если непусто — правило сейчас не
            # действует (apply_xray_config его пропускает), UI это
            # подсвечивает.
            "validation_warnings": invalid,
        }


# ---------------------------------------------------------------------------
# External outbound proxies (for cascade to external SOCKS5/HTTP)
# ---------------------------------------------------------------------------

class ExternalOutbound(db.Model):
    __tablename__ = "external_outbounds"

    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String(64), unique=True, nullable=False)
    protocol = db.Column(db.String(16), nullable=False)          # socks / http
    address = db.Column(db.String(256), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(128), nullable=True)
    password = db.Column(db.String(256), nullable=True)
    enabled = db.Column(db.Boolean, default=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tag": self.tag,
            "protocol": self.protocol,
            "address": self.address,
            "port": self.port,
            "username": self.username,
            "enabled": self.enabled,
        }


# ---------------------------------------------------------------------------
# Split-tunnel IP/domain lists
# ---------------------------------------------------------------------------

class SplitTunnelList(db.Model):
    __tablename__ = "split_tunnel_lists"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    list_type = db.Column(db.String(8), nullable=False)          # "domain" | "ip"
    action = db.Column(db.String(8), nullable=False)             # "direct" | "proxy" | "block"
    source_url = db.Column(db.String(512), nullable=True)        # remote URL to auto-update
    content = db.Column(db.Text, default="")                     # raw list, newline-separated
    last_updated = db.Column(db.DateTime, nullable=True)
    enabled = db.Column(db.Boolean, default=True)

    def get_entries(self) -> list[str]:
        return [line.strip() for line in self.content.splitlines() if line.strip() and not line.startswith("#")]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "list_type": self.list_type,
            "action": self.action,
            "source_url": self.source_url,
            "entry_count": len(self.get_entries()),
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "enabled": self.enabled,
        }


# ---------------------------------------------------------------------------
# Global settings (key-value)
# ---------------------------------------------------------------------------

class Setting(db.Model):
    __tablename__ = "settings"

    key = db.Column(db.String(128), primary_key=True)
    value = db.Column(db.Text, nullable=True)

    @staticmethod
    def get(key: str, default=None):
        row = db.session.get(Setting, key)
        return row.value if row else default

    @staticmethod
    def set(key: str, value: str):
        row = db.session.get(Setting, key)
        if row is None:
            row = Setting(key=key, value=value)
            db.session.add(row)
        else:
            row.value = value


# ---------------------------------------------------------------------------
# Audit log (этап 4)
# ---------------------------------------------------------------------------

class AuditLog(db.Model):
    """Журнал действий админов и системных событий.

    Главные принципы:
      - timestamp + action — ключевые индексы, всё остальное опционально
      - target_name дублирует ссылку на сущность, чтобы запись оставалась
        читаемой даже после удаления сущности
      - details — свободный JSON для контекста (что именно поменяли)
      - username может быть NULL — для системных событий (scheduler и т.п.)
    """
    __tablename__ = "audit_logs"

    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    username    = db.Column(db.String(64),  nullable=True)
    action      = db.Column(db.String(64),  nullable=False, index=True)
    target_type = db.Column(db.String(32),  nullable=True)
    target_id   = db.Column(db.Integer,     nullable=True)
    target_name = db.Column(db.String(256), nullable=True)
    ip          = db.Column(db.String(45),  nullable=True)   # IPv6 max ~39 + запас
    details     = db.Column(db.Text,        nullable=True)   # JSON-сериализованный dict

    def to_dict(self) -> dict:
        ts = self.timestamp
        if ts and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        details_obj = None
        if self.details:
            try:
                details_obj = json.loads(self.details)
            except (ValueError, TypeError):
                details_obj = {"raw": self.details}
        return {
            "id":          self.id,
            "timestamp":   ts.isoformat() if ts else None,
            "username":    self.username,
            "action":      self.action,
            "target_type": self.target_type,
            "target_id":   self.target_id,
            "target_name": self.target_name,
            "ip":          self.ip,
            "details":     details_obj,
        }
