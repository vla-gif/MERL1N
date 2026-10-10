"""Core: папки, логер, ключи, пиры, базовые команды. Вся бытовуха в одном файле."""
import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from ecdsa import SECP256k1, SigningKey

REPO = Path(__file__).resolve().parent.parent
OWNER_PUB = "0327a7f0c787506c7314c10a0f37242901bded4606e7f18d58959ca9be53355829"
MIN_ROLE = "viewer"
ROLES = ("viewer", "operator", "admin")

# модули, которые точка входа грузит явно (Wizard.load) — без скана папок;
# новый модуль: добавить файл + дописать имя в этот список
MOD_NAMES = ("modules.network", "modules.diag_mod", "modules.demo_mod")

_done = False


def app_dir(explicit=None) -> Path:
    if explicit:
        return Path(explicit)
    if (REPO / "storage").exists():
        return REPO / "storage"
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "data"
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", str(Path.home()))) / "MERL1N"
    return Path.home() / ".merlin"


def ensure(app: Path) -> dict:
    d = {"root": app, "data": app / "data", "logs": app / "logs"}
    for p in d.values():
        p.mkdir(parents=True, exist_ok=True)
    return d


def setup_logs(logdir: Path):
    global _done
    root = logging.getLogger("merlin")
    root.setLevel(logging.INFO)
    if not _done:
        f = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
        fh = RotatingFileHandler(logdir / "merlin.log", maxBytes=1_000_000,
                                 backupCount=3, encoding="utf-8")
        fh.setFormatter(f)
        sh = logging.StreamHandler()
        sh.setFormatter(f)
        root.addHandler(fh)
        root.addHandler(sh)
        _done = True
    return root


def log(name: str):
    return logging.getLogger(f"merlin.{name}")


class Keys:
    def __init__(self, data: Path):
        data.mkdir(parents=True, exist_ok=True)
        self.path = data / "id.json"
        self.data = data
        if self.path.exists():
            priv = SigningKey.from_string(
                bytes.fromhex(json.loads(self.path.read_text(encoding="utf-8"))["priv"]),
                curve=SECP256k1)
        else:
            priv = SigningKey.generate(curve=SECP256k1)
            self.path.write_text(json.dumps({"priv": priv.to_string().hex()}), encoding="utf-8")
        self.priv = priv
        self.pub = priv.get_verifying_key().to_string("compressed").hex()
        self.short = self.pub[:12]
        log("keys").info(f"pub={self.short}...")

    def rotate(self):
        self.path.unlink(missing_ok=True)
        fresh = Keys(self.data)
        self.priv, self.pub, self.short = fresh.priv, fresh.pub, fresh.short
        log("keys").info(f"rotated -> {self.short}... (re-pair everywhere)")


class Peers:
    def __init__(self, data: Path):
        self.path = data / "peers.json"
        data.mkdir(parents=True, exist_ok=True)
        self._d: dict = {}
        if self.path.exists():
            try:
                self._d = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self._d = {}

    def save(self):
        self.path.write_text(json.dumps(self._d, indent=2, ensure_ascii=False), encoding="utf-8")

    def known(self, pub: str) -> bool:
        return pub in self._d or pub == OWNER_PUB

    def add(self, pub: str, name: str, role: str):
        name = (name or "").strip() or pub[:12]
        role = (role or "").strip().lower() or MIN_ROLE
        if role not in ROLES:
            role = MIN_ROLE
        self._d[pub] = {"name": name, "role": role}
        self.save()

    def resolve(self, name_or_pub: str):
        if name_or_pub in self._d:
            return name_or_pub
        for pub, e in self._d.items():
            if e.get("name") == name_or_pub:
                return pub
        return None

    def label(self, pub: str) -> str:
        e = self._d.get(pub)
        return f"{e['name']} ({pub[:12]}...)" if e else pub[:12] + "..."

    def listed(self) -> dict:
        return {p: e for p, e in self._d.items() if p != OWNER_PUB}


def register_base(wizard):
    """Базовые команды (/help, /peers, /rotate) на любой экземпляр Wizard.

    Вызывается из точки входа до load(); повторный вызов безопасен."""
    mod = wizard.reg_mod("base") if "base" not in wizard.mods else wizard.mods["base"]

    @mod.command(command="help", desc="список команд")
    async def _help(message):
        await message.answer(wizard.help_lines(message.role, message.via_link))

    @mod.command(command="peers", desc="известные пиры (без owner)")
    async def _peers(ctx):
        lst = ctx.peers.listed()
        if not lst:
            return "no peers yet"
        return "\n".join(f"{e['name']} [{e['role']}] {p[:12]}..." for p, e in lst.items())

    @mod.command(command="quit", desc="выход")
    async def _quit():
        raise SystemExit(0)

    @mod.command(command="rotate", desc="сменить ключи", role="admin")
    async def _rotate(ctx):
        ctx.keys.rotate()
        return f"new pub={ctx.keys.pub} (restart, re-pair everywhere)"
