"""server: худая точка входа. Тот же движок, что и в client/client.py.

Диспетчер — core.wizard.Wizard: строка REPL -> envelope -> handle();
ответы хендлеров уходят через sender'ы (print в локальный REPL).
Модули грузятся явно (wizard.load), без скана папок; список — core.core.MOD_NAMES.
Сценарий сопряжения — modules/pairing_mod.py (FSM), диагностика — diag_mod.

OFFLINE: транспорт выкинут (modules/network.py -> trash_v2/network_dead.py).
Когда появится: исходящие — send() с непустым pub, события транспорта —
ctx.typer.feed("pair-request <pub> <id>") / pairing_mod.request()/mirror().
"""
import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.core import MOD_NAMES, Keys, Peers, app_dir, ensure, register_base, setup_logs
from core.typer import Typer
from core.wizard import Wizard


class Ctx:
    kind = "server"


async def main(app):
    dirs = ensure(app_dir(app))
    setup_logs(dirs["logs"])
    ctx = Ctx()
    ctx.data = dirs["data"]
    ctx.keys = Keys(dirs["data"])
    ctx.peers = Peers(dirs["data"])
    ctx.typer = Typer()
    wizard = Wizard()                   # свежий экземпляр на процесс
    wizard.set_my_pub(ctx.keys.pub)     # нормализация peer/ключа FSM
    wizard.set_sender(lambda text, pub="": print(text, flush=True))
    register_base(wizard)
    wizard.load(*MOD_NAMES)             # явная загрузка модулей (регистрация декораторов)
    wizard.set_input_source(ctx.typer.next_line)  # ask() сам подкачивает ввод REPL

    # Сеть живёт в modules/network.py (мод network): сокет + Router + сессии.
    # События транспорта: wizard.mods["network"].pair_request(ctx, pub, rid)
    ctx.net = None

    await wizard.startup(ctx)           # startup-хуки модулей
    print(f"SERVER pub={ctx.keys.pub}")
    print("text = chat | /connect <pub|name> | /links | /help | /peers | /rotate | /pair | /quit")
    ctx.typer.start()
    try:
        while True:
            line = (await ctx.typer.next_line()).strip()
            if not line:
                continue
            env = ctx.typer.envelope(line)
            await wizard.handle(ctx, env, via_link=False)
    except (SystemExit, KeyboardInterrupt):
        print("bye.")
    finally:
        await wizard.shutdown(ctx)      # shutdown-хуки + отмена fsm-таймеров


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-dir", default=None)
    a = ap.parse_args()
    asyncio.run(main(a.app_dir))
