"""Typer: stdin -> envelope dict. Только упаковка, без логики.

Формат envelope — контракт транспорта (см. core.wizard.build_message):
    {"from": <pub отправителя, "" = локальный ввод>,
     "message": {"text": [слова], "time": ["HH:MM:SS"]}}
"""
import asyncio
import sys
import time


class Typer:
    def __init__(self, my_pub: str = ""):
        self.my_pub = my_pub or ""
        self.q: asyncio.Queue = asyncio.Queue()

    def start(self):
        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, self._reader, loop)

    def _reader(self, loop):
        while True:
            try:
                line = sys.stdin.readline()
            except Exception:
                break
            if line == "":
                break
            asyncio.run_coroutine_threadsafe(self.q.put(line.strip()), loop)

    def envelope(self, text: str) -> dict:
        words = text.strip().split() if text.strip() else []
        ts = time.strftime("%H:%M:%S")
        return {"from": "", "pub": "",
                "message": {"text": words, "time": [ts]}}

    async def feed(self, line: str):
        """Программная подача строки в тот же stdin-очередь (события
        транспорта, например pair-request, кладутся сюда вместо отдельной
        очереди)."""
        await self.q.put((line or "").strip())

    async def next_line(self) -> str:
        return await self.q.get()

