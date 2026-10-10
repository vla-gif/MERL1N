"""demo_mod: эталонный модуль под новый API Wizard (aiogram-подобный стиль).

Регистрация без скана папок: файл сам создаёт свой Mod, точка входа явно
грузит его wizard.load("modules.demo_mod"). Хендлеры объявляются декораторами:

    @wizard.command(command="ping", desc="...", role="operator")  — /ping ...
    @wizard.text(Groups.state)                                    — FSM-хендлер
    @wizard.text()                                                — обычный чат
    @wizard.middleware(priority=1)                                — цепочка
    @wizard.error(MyError)                                        — перехват
    @wizard.startup / @wizard.shutdown                            — жизненный цикл

FSM в стиле aiogram: StatesGroup + State + FSContext(fsm_ctx)/MemoryStorage.
Одноразовый интерактив без состояний — await wizard.ask(prompt).

Запуск самопроверки: PYTHONPATH=/workspace python modules/demo_mod.py
"""
import asyncio

from core.wizard import State, StatesGroup, Wizard

wizard = Wizard.reg_mod("demo")


class PairError(Exception):
    """Своя ошибка модуля — её ловит @wizard.error ниже."""


class DemoFlow(StatesGroup):
    """Группа состояний демо-сценария (имя -> state, как в aiogram)."""
    ask_name = State()
    ask_role = State()


# ---------------------------------------------------------------- lifecycle
@wizard.startup
async def _startup(ctx):
    print("[demo] startup")


@wizard.shutdown
async def _shutdown(ctx):
    print("[demo] shutdown")


# ---------------------------------------------------------------- middleware
@wizard.middleware(priority=1)
async def audit(peer, role, via_link):
    print(f"[audit] peer={peer[:8] if peer else 'Lokal'}... role={role} "
          f"via_link={via_link}")
    # None -> пропускаем дальше; строка -> станет ответом;
    # StopProcessing -> съедаем молча.


# ------------------------------------------------------------------ команды
@wizard.command(command="ping", desc="пинговать хост", role="operator")
async def ping(host: str, timeout: float = 2.0, flags: dict = None):
    """Позиционные аргументы берутся из аннотаций (host: str, timeout: float),
    флаги --timeout=5 / -timeout 5 бинятся на параметр timeout автоматически."""
    repeat = int(flags.get("repeat", 1)) if flags else 1
    return f"ping {host} timeout={timeout}s repeat={repeat}"


@wizard.command(command="echo", desc="повторить текст")
async def echo_cmd(message):
    """/echo hello world -> message.text уже без имени команды."""
    return f"[echo] {message.text}"


@wizard.command(command="ask_demo", desc="одноразовый интерактив без FSM")
async def ask_demo(message):
    ans = await wizard.ask(prompt="назовите слово: ", pub=message.pub)
    return f"вы ввели: {ans!r}"


@wizard.command(command="boom", desc="демо-ошибка (для error-хука)", hidden=True)
async def boom():
    raise PairError("намеренная ошибка модуля demo")


# ----------------------------------------------------- FSM: таблица состояний
@wizard.command(command="demo_fsm", desc="запустить демо-FSM (ask_name -> ask_role)")
async def demo_fsm(fsm_ctx):
    await fsm_ctx.set(DemoFlow.ask_name)
    return "как тебя назвать?"


@wizard.text(DemoFlow.ask_name)
async def fsm_ask_name(message, fsm_ctx):
    await fsm_ctx.update_data(name=message.text)
    await fsm_ctx.set(DemoFlow.ask_role)
    return f"имя '{message.text}' принято, теперь роль (viewer/operator/admin):"


@wizard.text(DemoFlow.ask_role)
async def fsm_ask_role(message, fsm_ctx):
    d = dict(fsm_ctx.get_data())
    await fsm_ctx.finish()
    return f"FSM завершён: имя={d.get('name')} роль={message.text}"


# ------------------------------------------------------------- текстовый чат
@wizard.text(priority=5)
async def on_hello(message):
    if message.args and message.args[0].lower() in ("hi", "привет"):
        return f"здоровается модуль demo (слов: {len(message.args)})"
    # возвращаем None -> событие идёт дальше по цепочке


# ---------------------------------------------------------------- error hook
@wizard.error(PairError)
async def handle_pair_error(exception):
    return f"demo: перехвачено -> {exception}"


# ------------------------------------------------------- самостоятельная проверка
if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    from core.wizard import Wizard as Wz   # noqa: E402

    class PeersStub:
        _d = {}

        def add(self, pub, name, role):
            self._d[pub] = {"name": name, "role": role}

        def label(self, pub):
            return self._d.get(pub, {}).get("name", pub[:12])

        def resolve(self, x):
            return x if x in self._d else None

    class Ctx:
        kind = "server"
        peers = PeersStub()

    async def _selftest():
        wz = Wz()                       # локальный экземпляр, синглтон не трогаем
        sent = []
        wz.set_sender(lambda t, p: sent.append((p, t)))
        # этот файл уже наполнил pending мода "demo" в синглтоне;
        # для прогона собираем его декораторы в таблицы нового экземпляра
        wz.collect("demo")
        ctx = Ctx()

        def env(*words):
            return {"pub": "", "from": "", "message": {"text": list(words)}}

        async def run(*words):
            """handle() печатает ответы через sender — показываем новые строки."""
            mark = len(sent)
            await wz.handle(ctx, env(*words), False)
            for _p, t in sent[mark:]:
                print(t)

        await run("/ping", "8.8.8.8", "--timeout", "5")
        await run("/echo", "alias works")
        await run("hi there")
        await run("/boom")

        # FSM: запуск командой, дальше state-хендлеры перехватывают текст
        await run("/demo_fsm")
        await run("Alice")
        await run("operator")
        print("state after:", await wz.fsm.storage.get(""))

        # ask(): prompt уходит в sender, следующая реплика — в waiter
        task = asyncio.create_task(run("/ask_demo"))
        await asyncio.sleep(0.05)
        await run("word123")
        await task
        print("sent prompts:", [t for _p, t in sent if "слово" in t])

    asyncio.run(_selftest())
