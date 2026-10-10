"""Wizard: aiogram-подобный диспетчер MERL1N (переписан под чистую).

API модуля:

    from core.wizard import Wizard

    wizard = Wizard.reg_mod("mymod")           # объект-модуль (реестр хендлеров)

    @wizard.command(command="test_command", desc="описание для /help", role="admin")
    async def handler(message):
        await message.answer(message.text)

Точка входа:

    from core.wizard import wizard             # глобальный синглтон диспетчера
    wizard.set_sender(sender)                  # куда физически слать текст
    wizard.load("modules.pairing_mod", ...)    # явная загрузка (без скана папок)
    await wizard.startup(ctx); ...; await wizard.shutdown(ctx)
    reply = await wizard.handle(ctx, envelope, via_link=False)

Возможности:
  * Message — единый входной объект: pub/name/role/text/raw/args/flags/answer/send_to;
  * ролевая модель viewer < operator < admin < owner (role = минимальная роль,
    отказ — DENIED_TEXT);
  * FSM в стиле aiogram: StatesGroup / State / FSContext / MemoryStorage / StateFilter;
  * middlewares (priority-sorted), error handlers, startup/shutdown-хуки;
  * текстовые хендлеры с state-фильтрами; фильтры по содержимому — в коде;
  * строгая валидация имён команд + регистронезависимость; hidden-команды;
  * idle-таймауты состояний; выход из состояния — ctx.finish().

Легаси (WizardModule, command_handler/text_handler, Flow) удалены — весь код
проекта переведён на этот API.
"""
import asyncio
import importlib
import inspect
import re
from dataclasses import dataclass, field

from core.core import log as _log

# ------------------------------------------------------------------ константы
ROLES_ORDER = ("viewer", "operator", "admin", "owner")
DENIED_TEXT = "Отказано в доступе"
LOCAL_NAME = "Lokal"
LOCAL_ROLE = "owner"        # локальный REPL: owner по умолчанию (до rules про роли)
CMD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_MAX_ASK_DEPTH = 8               # вложенные ask() глубже — классическое ожидание

# имена, которые диспетчер инжектирует сам — они не позиционные аргументы
RESERVED = {"ctx", "message", "envelope", "peer", "role", "via_link",
            "raw", "text", "args", "flags", "state", "command", "fsm",
            "fsm_ctx"}


def _norm_cmd(name) -> str:
    """'/Cmd'/'cmd' -> 'cmd'; строгая валидация имени команды."""
    s = str(name or "").strip().lstrip("/").lower()
    if not CMD_RE.match(s):
        raise ValueError(f"некорректное имя команды {name!r}: "
                         f"ожидается [A-Za-z][A-Za-z0-9_]*")
    return s


def _role_at_least(actual, required) -> bool:
    try:
        ai = ROLES_ORDER.index(actual or "viewer")
    except ValueError:
        ai = 0
    try:
        ri = ROLES_ORDER.index(required or "viewer")
    except ValueError:
        ri = 0
    return ai >= ri


# --------------------------------------------------------------------- message
@dataclass
class Message:
    """Единый входной объект для всех хендлеров (команды, текст, FSM).

    Поля: pub/name/role/via_link/envelope/raw/text/args/flags/state.
    answer() шлёт автору сообщения, send_to() — конкретному адресату
    (pubkey или имя из peers).
    """
    pub: str = ""
    name: str = LOCAL_NAME
    role: str = LOCAL_ROLE
    via_link: bool = False
    envelope: dict = field(default_factory=dict)
    raw: str = ""
    text: str = ""
    args: list = field(default_factory=list)
    flags: dict = field(default_factory=dict)
    state: object = None
    wizard: "Wizard|None" = field(default=None, repr=False)

    @property
    def words(self):
        return self.args

    async def answer(self, text=""):
        """Ответ автору сообщения (его pub; локальный ввод -> pub='')."""
        if self.wizard is not None:
            await self.wizard.send(text, self.pub)

    async def send_to(self, target, text=""):
        """Отправка конкретному адресату: pubkey или имя из peers."""
        if self.wizard is not None:
            await self.wizard.send(text, self._resolve(target))

    def _resolve(self, target):
        if not target:
            return ""
        w = self.wizard
        ctx = getattr(w, "_ctx", None) if w else None
        peers = getattr(ctx, "peers", None) if ctx else None
        resolve = getattr(peers, "resolve", None)
        if callable(resolve):
            try:
                pub = resolve(str(target))
                if pub:
                    return pub
            except Exception:
                pass
        return str(target)


# ------------------------------------------------------------------------ fsm
class State:
    """Метка состояния. Внутри StatesGroup привязывается к группе автоматически."""

    def __init__(self):
        self._state = None
        self._group = None

    def __set_name__(self, owner, name):
        if isinstance(owner, type) and issubclass(owner, StatesGroup):
            self._state = name
            self._group = owner
            owner._states_[name] = self

    @property
    def state(self):
        return self._state

    @property
    def group(self):
        return self._group

    def __repr__(self):
        g = self._group.__name__ if self._group else "?"
        return f"<State {g}:{self._state}>"


class _StatesGroupMeta(type):
    def __new__(mcls, name, bases, ns):
        cls = super().__new__(mcls, name, bases, ns)
        merged = {}
        for b in reversed(cls.__mro__[1:]):
            merged.update(getattr(b, "_states_", {}) or {})
        for nm, v in ns.items():
            if isinstance(v, State):
                v.__set_name__(cls, nm)
                merged[nm] = v
        cls._states_ = merged
        return cls


class StatesGroup(metaclass=_StatesGroupMeta):
    """Группа состояний:

        class MyGroup(StatesGroup):
            first = State()
            second = State()
    """
    _states_: dict = {}


class FSContext:
    """Контекст FSM для хендлера: чтение/запись состояния и данных группы.

        @wizard.text(MyGroup.first)
        async def h(message, ctx_fsm: FSContext):
            await ctx_fsm.set(MyGroup.second)
            ctx_fsm.get_data()["tmp"] = message.text
            await ctx_fsm.update_data(a=1)
            await ctx_fsm.finish()          # выйти из группы
    """

    def __init__(self, fsm: "FSM", key, message: Message):
        self._fsm = fsm
        self._key = key
        self.message = message

    @property
    def key(self):
        return self._key

    async def set(self, state):
        await self._fsm.storage.set(self._key, state)
        self._fsm.touch(self._key)

    async def finish(self):
        await self._fsm.storage.set(self._key, None)
        self._fsm.data_of(self._key).clear()
        self._fsm.cancel_idle(self._key)

    def get_data(self) -> dict:
        return self._fsm.data_of(self._key)

    async def update_data(self, **kw):
        self.get_data().update(kw)
        self._fsm.touch(self._key)

    async def ask(self, prompt: str = "", timeout: float | None = None) -> str:
        """Спросить автора сообщения и дождаться его ответа (гибрид FSM).

        Печатает prompt адресату и вешает хендлер на следующую реплику этого
        же адреса; ответ диспатчер перехватывает раньше текстовых хендлеров.
        Возвращает строку ответа ('' при idle/timeout). Пока ждём, все
        команды адресата обрабатываются как обычно — блокируется только
        обычный текст.
        """
        w = self._fsm.wizard or self.message.wizard
        if w is None:
            raise RuntimeError("FSContext.ask: нет ссылки на Wizard")
        if prompt:
            await self.message.answer(prompt)
        return await w.wait_reply(self.message.pub, timeout=timeout)


class MemoryStorage:
    """Хранилище состояний per-key: {key: State}. Интерфейс open/async."""

    def __init__(self):
        self._d: dict = {}

    async def get(self, key):
        return self._d.get(key)

    async def set(self, key, state):
        if state is None:
            self._d.pop(key, None)
        else:
            self._d[key] = state

    async def clear(self, key):
        self._d.pop(key, None)


class StateFilter:
    """Фильтр: пропустить хендлер только если пир в указанных состояниях.

        @wizard.text(MyGroup.first)             # конкретное состояние
        @wizard.text([MyGroup.first, second])   # список состояний
        @wizard.text(MyGroup)                   # вся группа
        @wizard.text("*")                       # любое состояние
        @wizard.text(None)                      # только вне состояний
    """

    def __init__(self, states):
        items = states if isinstance(states, (list, tuple, set)) else [states]
        self.any_state = "*" in items
        self.default = None in items
        self.groups = {i for i in items
                       if isinstance(i, type) and issubclass(i, StatesGroup)}
        self.states = {i for i in items if isinstance(i, State)}

    def check(self, current) -> bool:
        if current is None:
            return self.default or self.any_state
        if self.any_state:
            return True
        if isinstance(current, State):
            if current in self.states:
                return True
            g = current.group
            if g is not None:
                if g in self.states:
                    return True
                if any(issubclass(g, gr) for gr in self.groups):
                    return True
        return False


def make_state_filter(states):
    if isinstance(states, StateFilter):
        return states
    return StateFilter(states)


class FSM:
    """Машина состояний: storage + промежуточные данные + idle-таймеры.

    wizard — обратная ссылка на диспетчер (ставится в Wizard.__init__) для
    ask(): очередь ожидания ответов лежит на Wizard, а не здесь.
    """

    def __init__(self, storage=None, idle: float | None = None):
        self.wizard = None                  # ставится Wizard'ом
        self.storage = storage or MemoryStorage()
        self.idle = idle                    # сек покоя до автосброса (global)
        self._idle_by_group: dict = {}      # group name -> seconds (override)
        self._data: dict = {}
        self._timers: dict = {}

    def data_of(self, key) -> dict:
        return self._data.setdefault(key, {})

    async def resolve_key(self, message: Message, group=None):
        """Ключ состояния для сообщения. Single-slot: одно состояние на пира.

        Группу игнорируем намеренно: set_state() из команд вызывается без
        группы (plain-ключ ""), а _dispatch_text ищет состояние с группой
        (("","DiagFlow")). С кортежным ключом они не совпадали и
        state-хендлеры /diag, /nics, /pair никогда не срабатывали.
        Фильтрация по группе всё равно работает через StateFilter.check()."""
        w = message.wizard
        pub = message.pub or ""
        if w is not None and pub and pub == getattr(w, "_my_pub", ""):
            pub = ""
        return pub

    async def get_state(self, message: Message, group=None):
        return await self.storage.get(await self.resolve_key(message, group))

    async def set_state(self, message: Message, state, group=None):
        key = await self.resolve_key(message, group)
        await self.storage.set(key, state)
        self.touch(key)

    async def get_context(self, message: Message, group=None) -> FSContext:
        return FSContext(self, await self.resolve_key(message, group), message)

    # ---- idle -------------------------------------------------------------
    def set_idle_group(self, group_name: str, seconds: float | None):
        """Override idle-таймера для состояний группы/мода."""
        if seconds is None:
            self._idle_by_group.pop(group_name, None)
        else:
            self._idle_by_group[group_name] = seconds

    def _idle_for(self, key):
        grp = key[1] if isinstance(key, tuple) else "*"
        return self._idle_by_group.get(grp, self.idle)

    def touch(self, key, secs=None):
        self.cancel_idle(key)
        if secs is None:
            secs = self._idle_for(key)
        if not secs:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._timers[key] = loop.call_later(secs, self._on_idle, key, secs)

    def cancel_idle(self, key):
        t = self._timers.pop(key, None)
        if t is not None:
            t.cancel()

    def _on_idle(self, key, secs):
        self._timers.pop(key, None)
        self._data.pop(key, None)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._drop_state(key))
        except RuntimeError:
            self.storage._d.pop(key, None)
        _log("wizard").info(f"fsm idle timeout: {key}")

    async def _drop_state(self, key):
        await self.storage.set(key, None)

    def cancel_all_timers(self):
        for key in list(self._timers):
            self.cancel_idle(key)


# -------------------------------------------------------------------- helpers
class UsageError(ValueError):
    """Недостаточно/неверное число позиционных аргументов -> 'usage: ...'."""


class StopProcessing(Exception):
    """Хендлер съел событие — дальше не идём, молча."""


def _cast(raw: str, p):
    ann = p.annotation
    if ann is inspect.Parameter.empty or ann is str:
        return raw
    try:
        if ann is int:
            return int(raw)
        if ann is float:
            return float(raw)
        if ann is bool:
            return raw.lower() not in ("0", "no", "n", "false", "")
    except ValueError:
        raise ValueError(f"'{raw}' for {p.name}")
    return raw


def _split_flags(args):
    """--flag val / --flag=val / -f -> (flags dict, позиционные)."""
    flags, pos = {}, []
    i = 0
    while i < len(args):
        a = str(args[i])
        if a.startswith("--"):
            if "=" in a:
                k, v = a[2:].split("=", 1)
                flags[k] = v
            else:
                key = a[2:]
                if i + 1 < len(args) and not str(args[i + 1]).startswith("-"):
                    flags[key] = args[i + 1]
                    i += 1
                else:
                    flags[key] = True
        elif a.startswith("-") and len(a) > 1 and not a[1].isdigit():
            key = a[1:]
            if i + 1 < len(args) and not str(args[i + 1]).startswith("-"):
                flags[key] = args[i + 1]
                i += 1
            else:
                flags[key] = True
        else:
            pos.append(a)
        i += 1
    return flags, pos


def _accepts(fn, name) -> bool:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    return name in sig.parameters


# ------------------------------------------------------------------- handlers
@dataclass
class Handler:
    fn: object
    kind: str = "command"
    name: str = ""               # cmd без слэша
    desc: str = ""
    role: str = "viewer"
    hidden: bool = False
    priority: int = 10
    module: str = ""
    params: set = field(default_factory=set)
    sig: object = None
    sfilt: object = None         # StateFilter|None (для text)
    idle: object = None          # сек. покоя до автосброса (для text-state)


def _make_handler(fn, meta, module, kind) -> Handler:
    sig = inspect.signature(fn)
    params = {p.name for p in sig.parameters.values()
              if p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                            inspect.Parameter.POSITIONAL_OR_KEYWORD,
                            inspect.Parameter.KEYWORD_ONLY)}
    return Handler(fn=fn, kind=kind, name=meta.get("name", ""),
                   desc=meta.get("desc", ""), role=meta.get("role", "viewer"),
                   hidden=meta.get("hidden", False),
                   priority=meta.get("priority", 10), module=module,
                   params=params, sig=sig,
                   sfilt=meta.get("sfilt"), idle=meta.get("idle"))


# ----------------------------------------------------------------------- mod
class Mod:
    """Объект модуля: Wizard.reg_mod(name) -> mod. Декораторы мода навешивают
    метаданные на функции; Wizard.load(...) собирает их в таблицы диспетчера.

    Хендлеры можно объявлять двумя способами:
      1) прямо в теле файла модуля:  wizard = Wizard.reg_mod("x"); @wizard.command(...)
      2) методами класса-обёртки:    register(wiz) внутри вызывает декораторы.
    Оба пути приводят к одному — регистрация идёт через экземпляр Mod.

    pending — метаданные хендлеров ({..., "_fn": fn}); их собирает в таблицы
    диспетчера Wizard.load(...) или Wizard.collect(...) (для selftest'ов).
    Один Mod может обслуживать несколько экземпляров Wizard: collect()
    переносит pending в таблицы конкретного экземпляра, оригинал не портится.
    """

    def __init__(self, name: str, wizard: "Wizard"):
        self.name = name
        self.wizard = wizard
        self.pending: list = []          # [{"kind": ..., "_fn": fn}]
        self._idle: float | None = None

    def _reg(self, meta: dict, fn):
        """Метаданные с функцией; сборка в таблицы — на load()/collect()."""
        meta["_fn"] = fn
        self.pending.append(meta)

    # ------------------------------------------------------------- lifecycle
    def startup(self, fn=None):
        """@wizard.startup — код при старте диспетчера (await wizard.startup(ctx))."""
        def deco(f):
            self._reg({"kind": "startup"}, f)
            return f
        return deco(fn) if fn is not None else deco

    def shutdown(self, fn=None):
        """@wizard.shutdown — код при остановке (await wizard.shutdown(ctx))."""
        def deco(f):
            self._reg({"kind": "shutdown"}, f)
            return f
        return deco(fn) if fn is not None else deco

    # ------------------------------------------------------------- handlers
    def command(self, command=None, desc="", role="viewer", hidden=False,
                priority=10, name=None):
        """Slash-команда '/command'. role — минимальная роль (viewer/operator/admin/owner)."""
        cname = _norm_cmd(command if command is not None else name)

        def deco(fn):
            self._reg({"kind": "command", "name": cname, "desc": desc,
                       "role": role, "hidden": hidden,
                       "priority": priority}, fn)
            return fn
        return deco

    def text(self, state=None, priority=10, role="viewer", idle: float | None = None):
        """Текстовый хендлер (не-команда).

        state — фильтр FSM-состояния в стиле aiogram:
          State/StatesGroup/list  — только в этих состояниях;
          "*"                     — в любом состоянии;
          None (по умолчанию)     — только вне состояний (обычный чат).
        Фильтры по содержимому сообщения — внутри кода хендлера.
        idle — сек. покоя до автосброса состояния этого сценария.
        """
        def deco(fn):
            sfilt = make_state_filter([state])   # None => default-фильтр
            self._reg({"kind": "text", "priority": priority,
                       "role": role, "sfilt": sfilt,
                       "idle": idle}, fn)
            return fn
        return deco

    def middleware(self, priority=10):
        def deco(fn):
            self._reg({"kind": "middleware", "priority": priority}, fn)
            return fn
        return deco

    def error(self, *exc_types):
        """@wizard.error(MyError) — перехват исключений хендлеров."""
        def deco(fn):
            self._reg({"kind": "error",
                       "exceptions": exc_types or (Exception,)}, fn)
            return fn
        return deco

    # ------------------------------------------------------------ interactive
    async def ask(self, prompt: str = "", timeout: float | None = None,
                  pub: str = "") -> str:
        """Одноразовый интерактив без FSM (для команд-скриптов типа /diag).

        Шлёт prompt адресу pub ('' = локальный вывод) и ждёт следующую
        текстовую реплику того же адреса; команды в это время обрабатываются
        как обычно. Возвращает '' при timeout/отмене.
        """
        await self.wizard.send(prompt, pub)
        return await self.wizard.wait_reply(pub, timeout=timeout)


# -------------------------------------------------------------------- wizard
class Wizard:
    """Диспетчер: реестр всех модов, диспатч, FSM, отправка."""

    _instance = None

    # NOTE: Wizard — синглтон на процесс (__new__ возвращает единственный
    # экземпляр). Точка входа вызывает Wizard.reset() перед конфигурацией,
    # чтобы повторный запуск в одном процессе не наследовал старый реестр.

    def __new__(cls):
        # единственный экземпляр на процесс: и wizard, и Wizard() в точках
        # входа возвращают один и тот же диспетчер (модули регистрируются
        # через Wizard.reg_mod -> instance(), сам singleton создаётся здесь).
        if cls._instance is None:
            inst = super().__new__(cls)
            cls._instance = inst
        return cls._instance

    def __init__(self):
        if getattr(self, "_inited", False):
            return
        self._inited = True
        self._logger = _log("wizard")
        self.mods: dict = {}              # name -> Mod
        self.commands: dict = {}          # cmd -> Handler
        self.text_handlers: list = []     # Handler (sorted by priority)
        self.middlewares: list = []
        self.error_handlers: list = []    # (exc_types, Handler)
        self.startup_hooks: list = []     # (module, fn)
        self.shutdown_hooks: list = []
        self.mod_idle: dict = {}          # mod name -> idle seconds
        self.fsm = FSM(idle=None)
        self.fsm.wizard = self
        self._sender = None
        self._my_pub = ""
        self._ctx = None
        self._loaded: set = set()
        self._waiters: dict = {}          # pub -> asyncio.Future (ask())
        self._input_source = None         # callable() -> awaitable[str] (для ask)
        self._ask_depth = 0               # глубина реентерабельных ask()

    # ------------------------------------------------------------ синглтон
    @classmethod
    def instance(cls) -> "Wizard":
        return cls()                      # __new__ гарантирует единственный экземпляр

    def reg_mod(self, name: str) -> "Mod":
        """Регистрация модуля без скана папки. Как instance-метод и как
        Wizard.reg_mod("x") (classmethod ниже — через глобальный экземпляр).

        Делегирует в _reg_mod_impl, а не в себя: класс-обёртка
        Wizard.reg_mod = classmethod(...) перекрывает этот метод на уровне
        класса, прямая рекурсия по self.reg_mod зациклила бы вызов."""
        return self._reg_mod_impl(name)

    def _reg_mod_impl(self, name: str) -> "Mod":
        if name in self.mods:
            raise ValueError(f"mod {name!r} уже зарегистрирован")
        m = Mod(name, self)
        self.mods[name] = m
        return m

    def reset(self):
        """Полная очистка диспетчера (для повторного запуска/тестов)."""
        for fut in self._waiters.values():
            if not fut.done():
                fut.cancel()
        self._waiters.clear()
        self._ask_depth = 0
        self.fsm.cancel_all_timers()
        self.mods.clear()
        self.commands.clear()
        self.text_handlers.clear()
        self.middlewares.clear()
        self.error_handlers.clear()
        self.startup_hooks.clear()
        self.shutdown_hooks.clear()
        self.mod_idle.clear()
        self._loaded.clear()
        # pending-декораторы файлов модулей (Wizard.reg_mod -> instance())
        # не должны переживать reset: иначе повторный load соберёт их второй раз
        inst = Wizard.instance()
        for m in list(inst.mods.values()):
            m.pending.clear()
        if inst is not self:
            Wizard._instance = None
        self.fsm = FSM()
        self.fsm.wizard = self

    # -------------------------------------------------------------- sender
    def set_sender(self, sender):
        """sender(text, pub) -> str|None; pub='' значит локальный вывод.
        Может быть sync или async."""
        self._sender = sender

    def set_my_pub(self, pub: str):
        self._my_pub = pub or ""

    def set_input_source(self, source):
        """Источник входящих строк для реентерабельного ask(): callable без
        аргументов, возвращающий awaitable со следующей строкой (str).
        В REPL-точках входа: wizard.set_input_source(ctx.typer.next_line)."""
        self._input_source = source

    async def send(self, text, pub=""):
        if text is None or text == "":
            return
        if self._sender is None:
            self._logger.warning(f"no sender, drop: {str(text)[:60]}")
            return
        r = self._sender(str(text), pub or "")
        if inspect.isawaitable(r):
            r = await r
        return r

    # ---------------------------------------------------------------- load
    def load(self, *names: str):
        """Явная загрузка модулей вместо скана папки: импорт python-модулей.
        Каждый модуль при импорте вызывает Wizard.reg_mod(...) и получает свой
        Mod; все хендлеры, зарегистрированные в нём ПОСЛЕ этого (декораторами),
        собираются здесь же — по одному снимку pending на каждый импорт."""
        for nm in names:
            if nm in self._loaded:
                continue
            before = {k: len(m.pending) for k, m in self.mods.items()}
            importlib.import_module(nm)
            self._loaded.add(nm)
            # файлы модулей декорируют через Wizard.reg_mod -> instance();
            # если self — другой экземпляр, подтягиваем его mods сюда
            inst = Wizard.instance()
            if inst is not self:
                for k, m in inst.mods.items():
                    if k not in self.mods and any(
                            x.get("_fn") is not None for x in m.pending):
                        c = Mod(k, self)
                        c.pending = list(m.pending)
                        c._idle = m._idle
                        self.mods[k] = c
            self._collect_pending(before)
        
        # После загрузки всех модулей собираем всё, что осталось pending
        # (включая base-команды, зарегистрированные до load())
        remaining_before = {k: len(m.pending) for k, m in self.mods.items()}
        self._collect_pending({})

    def collect(self, mod_name: str):
        """Собрать pending мода в таблицы ЭТОГО экземпляра. Нужно selftest'ам
        модулей, чьи декораторы живут в синглтоне: wz.reset(); wz.collect("demo")."""
        src_mod = self.mods.get(mod_name) or Wizard.instance().mods.get(mod_name)
        if src_mod is None:
            raise ValueError(f"mod {mod_name!r} не зарегистрирован")
        if src_mod.wizard is self:
            self._collect_pending({})
            return self.mods[mod_name]
        copy = Mod(mod_name, self)
        copy.pending = list(src_mod.pending)
        copy._idle = src_mod._idle
        self.mods[mod_name] = copy
        self._collect_pending({})
        return copy

    def _collect_pending(self, before: dict | None = None):
        """Переносит pending-хендлеры модов в таблицы диспетчера.
        before — снимки длин pending до импорта: собираем только то, что
        добавил этот импорт; старое (уже собранное) остаётся нетронутым."""
        for name, m in list(self.mods.items()):
            skip = before.get(name, 0) if before is not None else 0
            for meta in m.pending[skip:]:
                self._register_meta(m, meta, meta["_fn"])
            del m.pending[skip:]
            if m._idle is not None:
                self.mod_idle[m.name] = m._idle

    def _register_meta(self, m: Mod, meta: dict, fn):
        kind = meta["kind"]
        if kind == "command":
            h = _make_handler(fn, meta, m.name, "command")
            if h.name in self.commands:
                raise ValueError(f"команда /{h.name} уже занята "
                                 f"(модуль {self.commands[h.name].module})")
            self.commands[h.name] = h
        elif kind == "text":
            h = _make_handler(fn, meta, m.name, "text")
            self.text_handlers.append(h)
            self.text_handlers.sort(key=lambda x: x.priority)
        elif kind == "middleware":
            self.middlewares.append(_make_handler(fn, meta, m.name, "middleware"))
            self.middlewares.sort(key=lambda x: x.priority)
        elif kind == "error":
            self.error_handlers.append((meta.get("exceptions", (Exception,)),
                                        _make_handler(fn, meta, m.name, "error")))
        elif kind == "startup":
            self.startup_hooks.append((m.name, fn))
        elif kind == "shutdown":
            self.shutdown_hooks.append((m.name, fn))
        m.wizard = self

    # ------------------------------------------------------------ lifecycle
    async def startup(self, ctx=None):
        self._ctx = ctx
        for nm, fn in self.startup_hooks:
            try:
                r = fn(ctx) if _accepts(fn, "ctx") else fn()
                if inspect.isawaitable(r):
                    await r
            except Exception as e:
                self._logger.error(f"startup {nm} failed: {e!r}", exc_info=True)

    async def shutdown(self, ctx=None):
        for nm, fn in reversed(self.shutdown_hooks):
            try:
                r = fn(ctx) if _accepts(fn, "ctx") else fn()
                if inspect.isawaitable(r):
                    await r
            except Exception as e:
                self._logger.error(f"shutdown {nm} failed: {e!r}")
        self.fsm.cancel_all_timers()

    # ---------------------------------------------------------- waiters (ask)
    async def wait_reply(self, pub: str = "", timeout: float | None = None,
                         ctx=None, typer=None) -> str:
        """Дождаться следующей текстовой реплики от адреса pub (для FSContext.ask).
        Одна ожидающая корутина на адрес; timeout=None — без таймера.

        Реентерабельность: в offline-REPL внешний цикл висит в
        `await handle(команда_с_ask)` и не может прочитать следующую строку
        сам. Поэтому пока ждём, ask() сам подкачивает строки из источника
        ввода (ctx.typer.next_line / self._input_source / typer.next_line) и
        прогоняет их через handle() — команды в это время обрабатываются
        как обычно (docstring ask), а реплика нашего адреса будит waiter."""
        loop = asyncio.get_running_loop()
        old = self._waiters.pop(pub or "", None)
        if old is not None and not old.done():
            old.cancel()
        fut = loop.create_future()
        self._waiters[pub or ""] = fut
        pump = (self._ask_depth < _MAX_ASK_DEPTH and
                self._has_input_source(ctx or self._ctx, typer))
        if pump:
            try:
                return await self._pump_reply(fut, pub or "", timeout, ctx, typer)
            finally:
                if self._waiters.get(pub or "") is fut:
                    self._waiters.pop(pub or "", None)
        try:
            if timeout is None:
                return await fut
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            return ""
        except asyncio.CancelledError:
            return ""
        finally:
            if self._waiters.get(pub or "") is fut:
                self._waiters.pop(pub or "", None)

    def _resolve_waiter(self, pub: str, text: str) -> bool:
        """Если для адреса есть waiter — съесть реплику и разбудить ask()."""
        fut = self._waiters.get(pub or "")
        if fut is None or fut.done():
            return False
        fut.set_result(text or "")
        self._waiters.pop(pub or "", None)
        return True

    def _has_input_source(self, ctx, typer) -> bool:
        t = typer or (getattr(ctx, "typer", None) if ctx is not None else None)
        if callable(getattr(t, "next_line", None)):
            return True
        return callable(self._input_source) or callable(
            getattr(getattr(self._ctx, "typer", None), "next_line", None))

    async def _input_line(self, ctx, typer):
        ctx = ctx if ctx is not None else self._ctx
        src = None
        t = typer or (getattr(ctx, "typer", None) if ctx is not None else None)
        get = getattr(t, "next_line", None)
        if callable(get):
            src = get
        elif callable(self._input_source):
            src = self._input_source
        if src is None:
            get2 = getattr(getattr(self._ctx, "typer", None), "next_line", None)
            if callable(get2):
                src = get2
        if src is None:
            return None
        r = src()
        if inspect.isawaitable(r):
            r = await r
        return r

    def _pump_envelope(self, ctx, line: str, via_link_default: bool = False):
        ctx = ctx if ctx is not None else self._ctx
        t = getattr(ctx, "typer", None) if ctx is not None else None
        env_maker = getattr(t, "envelope", None)
        if callable(env_maker):
            return env_maker(line), False
        words = str(line or "").strip().split()
        return ({"from": "", "pub": "",
                 "message": {"text": words}}, via_link_default)

    async def _pump_reply(self, fut, pub: str, timeout, ctx, typer) -> str:
        """Качать входные строки через handle(), пока fut не разрешится.

        futures-гонка: ждём либо строку из источника, либо сам fut (его мог
        разрешить параллельный handle() — транспорт/GUI/selftest). Пустые
        строки пропускаем, но НЕ съедаем их из источника молча в ущерб
        внешнему циклу — внешний цикл всё равно читает из той же очереди,
        и строка уже обработана здесь, дублировать её не нужно."""
        self._ask_depth += 1
        loop = asyncio.get_running_loop()
        deadline = None if timeout is None else loop.time() + timeout
        try:
            while not fut.done():
                rest = None
                if deadline is not None:
                    rest = max(0.0, deadline - loop.time())
                    if rest <= 0:
                        if not fut.done():
                            fut.cancel()
                        break
                get_task = asyncio.ensure_future(self._input_line(ctx, typer))
                wait_task = asyncio.ensure_future(asyncio.shield(fut))
                done = set()
                try:
                    done, _ = await asyncio.wait(
                        {get_task, wait_task}, timeout=rest,
                        return_when=asyncio.FIRST_COMPLETED)
                except asyncio.CancelledError:
                    for t in (get_task, wait_task):
                        if not t.done():
                            t.cancel()
                    raise
                if wait_task in done:
                    if not get_task.done():
                        get_task.cancel()
                    try:
                        return wait_task.result()
                    except asyncio.CancelledError:
                        try:
                            return fut.result()
                        except Exception:
                            return ""
                if get_task in done:
                    if not wait_task.done():
                        wait_task.cancel()
                    try:
                        line = get_task.result()
                    except asyncio.CancelledError:
                        continue
                    except (SystemExit, KeyboardInterrupt):
                        raise
                    except Exception:
                        await asyncio.sleep(0)
                        continue
                    if line is None or not str(line).strip():
                        continue
                    env, via_link = self._pump_envelope(ctx, line)
                    use_ctx = ctx if ctx is not None else self._ctx
                    try:
                        await self.handle(use_ctx, env, via_link=via_link)
                    except (SystemExit, KeyboardInterrupt):
                        raise
                    except asyncio.CancelledError:
                        if fut.done():
                            try:
                                return fut.result()
                            except Exception:
                                return ""
                        raise
                    except Exception as e:
                        self._logger.error(f"pump handle failed: {e!r}",
                                           exc_info=True)
                        continue
                    continue
                if not get_task.done():
                    get_task.cancel()
                if not wait_task.done():
                    wait_task.cancel()
                if rest is not None:
                    if not fut.done():
                        fut.cancel()
                    break
                await asyncio.sleep(0)
            if fut.done():
                try:
                    return fut.result()
                except (asyncio.CancelledError, Exception):
                    return ""
            return ""
        finally:
            self._ask_depth = max(0, self._ask_depth - 1)

    # ---------------------------------------------------------------- roles
    def role_of(self, ctx, peer_pub) -> str:
        """Локальный ввод (pub пуст или равен нашему pubkey) — LOCAL_ROLE;
        иначе роль из peers (неизвестный пир = viewer)."""
        me = self._my_pub or ""
        if not peer_pub or (me and peer_pub == me):
            return LOCAL_ROLE
        peers = getattr(ctx, "peers", None)
        e = (peers._d.get(peer_pub)
             if peers is not None and hasattr(peers, "_d") else None)
        return (e or {}).get("role", "viewer")

    # --------------------------------------------------------------- parse
    def build_message(self, ctx, envelope, via_link) -> Message:
        words = (envelope.get("message") or {}).get("text", []) or []
        raw = " ".join(str(w) for w in words)
        peer = envelope.get("from", envelope.get("pub", ""))
        role = self.role_of(ctx, peer)
        local = (not peer) or (self._my_pub and peer == self._my_pub)
        name = LOCAL_NAME if local else None
        if name is None:
            peers = getattr(ctx, "peers", None)
            label = getattr(peers, "label", None)
            name = (label(peer) if callable(label) and peer
                    else (peer[:12] + "..." if peer else LOCAL_NAME))
        return Message(pub=peer, name=name, role=role, via_link=bool(via_link),
                       envelope=envelope, raw=raw, text=raw,
                       args=[str(w) for w in words], wizard=self)

    @staticmethod
    def parse_command(message: Message):
        """'/cmd остальное...' -> ('cmd', [args]); None если это не команда.
        Команда = ровно одно слово после '/' ([A-Za-z0-9_]), всё после — данные."""
        words = message.args
        if not words or not str(words[0]).startswith("/"):
            return None
        token = str(words[0])[1:]
        if not CMD_RE.match(token):
            return None          # '/bad-name!' — не команда, а обычный текст
        return token.lower(), [str(w) for w in words[1:]]

    # --------------------------------------------------------------- usage
    def usage_of(self, h: Handler) -> str:
        parts = []
        for p in h.sig.parameters.values():
            if p.name in RESERVED or p.kind == inspect.Parameter.VAR_POSITIONAL:
                continue
            if p.default is inspect.Parameter.empty:
                parts.append(f"<{p.name}>")
            elif p.annotation is bool:
                parts.append(f"[--{p.name}]")
            else:
                parts.append(f"[{p.name}]")
        full = "/" + h.name
        return f"{full} " + " ".join(parts) if parts else full

    def help_lines(self, role: str, via_link: bool) -> str:
        lines = []
        for name, h in sorted(self.commands.items()):
            if h.hidden:
                continue
            if via_link and not _role_at_least(role, h.role):
                continue
            line = self.usage_of(h)
            if h.desc:
                line += f" - {h.desc}"
            lines.append(line)
        return "cmds:\n" + "\n".join(lines)

    # ------------------------------------------------------------ dispatch
    async def handle(self, ctx, envelope, via_link: bool):
        """Диспатч одного события. Ответы хендлеров (строки/awaitables)
        уходят адресату через send() сами; возвращает True если событие
        было обработано (команда найдена / текст съеден), False — тишина."""
        self._ctx = ctx
        message = self.build_message(ctx, envelope, via_link)

        for mw in self.middlewares:
            try:
                r = await self._call_filtered(mw, self._event_kwargs(ctx, message,
                                                                     envelope, via_link))
            except StopProcessing:
                return True
            except (SystemExit, KeyboardInterrupt):
                raise
            except Exception as e:
                await self._reply(message,
                                  await self._on_error(e, {"ctx": ctx, "message": message}))
                return True
            if r is not None:
                await self._reply(message, r)
                return True

        parsed = self.parse_command(message)
        if parsed:
            r = await self._dispatch_command(ctx, message, parsed)
            await self._reply(message, r)
            return True
        r = await self._dispatch_text(ctx, message, envelope, via_link)
        await self._reply(message, r)
        return r is not None

    async def _reply(self, message: Message, r):
        """Shorthand возврата: строка из хендлера = ответ автору сообщения."""
        if r is None or r == "":
            return
        await self.send(str(r), message.pub)

    @staticmethod
    def _event_kwargs(ctx, message, envelope, via_link) -> dict:
        return {"ctx": ctx, "message": message, "envelope": envelope,
                "peer": message.pub, "role": message.role, "via_link": via_link,
                "raw": message.raw, "text": message.text,
                "args": message.args, "flags": message.flags,
                "state": message.state}

    async def _dispatch_command(self, ctx, message: Message, parsed):
        name, rest = parsed
        h = self.commands.get(name)
        if h is None:
            return f"unknown /{name}, try /help"
        if message.via_link and not _role_at_least(message.role, h.role):
            return DENIED_TEXT
        flags, pos = _split_flags(rest)
        kwargs = self._event_kwargs(ctx, message, message.envelope, message.via_link)
        kwargs["flags"] = flags
        kwargs["command"] = "/" + name
        for p in h.sig.parameters.values():
            if p.name in RESERVED or p.kind == inspect.Parameter.VAR_POSITIONAL:
                continue
            if p.name in flags:
                try:
                    kwargs[p.name] = _cast(str(flags[p.name]), p)
                except ValueError as e:
                    return f"bad arg: {e}"
                del flags[p.name]
        message.args = pos
        message.text = " ".join(pos)
        kwargs["args"] = pos
        kwargs["text"] = message.text
        try:
            self._bind_positional(h, pos, kwargs)
        except UsageError as e:
            return f"usage: {e}"
        except ValueError as e:
            return f"bad arg: {e}"
        kwargs["fsm"] = self.fsm
        # fsm_ctx вне состояния (для команд-инициаторов FSM, см. demo_fsm):
        # группа берётся из StateFilter'ов текстовых хендлеров мода этой команды
        if "fsm_ctx" in h.params:
            grp = None
            for th in self.text_handlers:
                if th.module == h.module and th.sfilt is not None:
                    if th.sfilt.states:
                        grp = next(iter(th.sfilt.states)).group
                        break
                    if th.sfilt.groups:
                        grp = next(iter(th.sfilt.groups))
                        break
            kwargs["fsm_ctx"] = await self.fsm.get_context(message, grp)
        try:
            return await self._call_filtered(h, kwargs)
        except StopProcessing:
            return None
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception as e:
            return await self._on_error(e, {"ctx": ctx, "message": message,
                                            "command": "/" + name})

    async def _dispatch_text(self, ctx, message: Message, envelope, via_link):
        """Сначала waiter'ы ask() (у них нет StateFilter — не трогаем
        message.state), затем текстовые хендлеры по priority; каждый
        пропускается своим StateFilter. Состояние для группы фильтра
        читается лениво и кешируется на время диспатча."""
        if self._resolve_waiter(message.pub, message.text):
            return ""                      # реплика ушла в ask(), чат молчит
        cur_cache: dict = {}
        for h in sorted(self.text_handlers, key=lambda x: x.priority):
            grp = None
            if h.sfilt is not None:
                if h.sfilt.states:
                    grp = next(iter(h.sfilt.states)).group
                elif h.sfilt.groups:
                    grp = next(iter(h.sfilt.groups))
            ck = grp.__name__ if grp else "*"
            if ck not in cur_cache:
                cur_cache[ck] = await self.fsm.get_state(message, grp)
            cur = cur_cache[ck]
            if h.sfilt is not None and not h.sfilt.check(cur):
                continue
            message.state = cur
            r = await self._run_text(h, ctx, message, envelope, via_link, cur)
            if r is not None:
                return r
        return None

    async def _run_text(self, h: Handler, ctx, message: Message,
                        envelope, via_link, cur_state) -> str | None:
        if via_link and not _role_at_least(message.role, h.role):
            return None
        kwargs = self._event_kwargs(ctx, message, envelope, via_link)
        kwargs["state"] = cur_state
        if cur_state is not None:
            grp = cur_state.group if isinstance(cur_state, State) else None
            kwargs["fsm_ctx"] = await self.fsm.get_context(message, grp)
            key = kwargs["fsm_ctx"].key
            idle = h.idle if h.idle is not None else self.mod_idle.get(h.module)
            self.fsm.touch(key, idle)
        else:
            kwargs["fsm_ctx"] = await self.fsm.get_context(message)
        try:
            return await self._call_filtered(h, kwargs)
        except StopProcessing:
            return ""
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception as e:
            await self._on_error(e, {"ctx": ctx, "message": message})
            return None

    # --------------------------------------------------------------- errors
    async def _on_error(self, exc, event):
        for types, h in self.error_handlers:
            if isinstance(exc, types):
                kw = {"exception": exc, "ctx": event.get("ctx"),
                      "message": event.get("message")}
                try:
                    r = await self._call_filtered(h, kw)
                    if r is not None:
                        return r
                except Exception as inner:
                    self._logger.error(f"error handler failed: {inner!r}")
        self._logger.error(f"unhandled: {exc!r}", exc_info=True)
        return f"failed: {exc!r} [{type(exc).__name__}]"

    # -------------------------------------------------------------- calling
    @staticmethod
    def _params_of(fn) -> set:
        try:
            sig = inspect.signature(fn)
        except (TypeError, ValueError):
            return set()
        return {p.name for p in sig.parameters.values()
                if p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                              inspect.Parameter.POSITIONAL_OR_KEYWORD,
                              inspect.Parameter.KEYWORD_ONLY)}

    async def _call_filtered(self, h: Handler, kwargs: dict):
        call_kw = {k: v for k, v in kwargs.items() if k in h.params}
        r = h.fn(**call_kw)
        if inspect.isawaitable(r):
            r = await r
        return r

    @staticmethod
    def _bind_positional(h: Handler, rest: list, kwargs: dict):
        need = [p for p in h.sig.parameters.values()
                if p.name not in RESERVED and p.default is inspect.Parameter.empty
                and p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                               inspect.Parameter.POSITIONAL_OR_KEYWORD)]
        if len(rest) < len(need):
            want = " ".join(f"<{p.name}>" for p in need)
            raise UsageError(f"/{h.name} {want}".strip())
        for p in h.sig.parameters.values():
            if p.name in RESERVED or p.name in kwargs:
                continue
            if p.kind == inspect.Parameter.VAR_POSITIONAL:
                kwargs[p.name] = rest
                rest = []
            elif rest:
                kwargs[p.name] = _cast(rest.pop(0), p)
            elif p.default is not inspect.Parameter.empty:
                kwargs[p.name] = p.default


# ------------------------------------------------------------------ singleton
def _reg_mod(cls, name: str) -> Mod:
    """Класс-обёртка: Wizard.reg_mod("x") -> reg_mod глобального экземпляра.
    На инстансе тот же метод доступен как wizard.reg_mod("x")."""
    return cls.instance()._reg_mod_impl(name)


Wizard.reg_mod = classmethod(_reg_mod)

wizard = Wizard()                        # синглтон: к нему обращаются
# Wizard.instance()/Mod'ы файлов модулей (Wizard.reg_mod на уровне класса).
# Точки входа создают СВЕЖИЙ экземпляр Wizard(); файлы модулей при импорте
# вешают хендлеры на синглтон, а load(...) экземпляра подхватывает их через
# Wizard.instance().mods (см. Wizard.load/_collect_pending).
