"""Context: контейнер модулей (Router) для Wizard.

Message/парсинг живут в core.wizard; здесь только реестр объектов модулей,
чтобы чужой код мог достучаться до публичного API модуля по имени:
router.get("pairing").request(...). Никаких зависимостей от core.wizard.
"""
import asyncio


class Router:
    """Контейнер состояния модулей: router.get("diag") -> объект модуля."""

    def __init__(self):
        self._modules: dict = {}
        self._meta: dict = {}
        # алиас под старое usage в diag_mod: getattr(ctx.net, "router", None)
        self.protected_clients: set = set()

    def register(self, name: str, obj, meta: dict | None = None):
        self._modules[name] = obj
        if meta:
            self._meta[name] = meta

    def get(self, name: str, default=None):
        return self._modules.get(name, default)

    def has(self, name: str) -> bool:
        return name in self._modules

    def names(self):
        return sorted(self._modules)

    def meta(self, name: str, key: str, default=None):
        return self._meta.get(name, {}).get(key, default)

    async def shutdown_all(self):
        """Последовательно дёргает stop()/close() у всех модулей."""
        for name in list(self._modules):
            m = self._modules[name]
            for meth in ("stop", "close"):
                fn = getattr(m, meth, None)
                if callable(fn):
                    try:
                        r = fn()
                        if asyncio.iscoroutine(r):
                            await asyncio.wait_for(r, timeout=5)
                    except Exception:
                        pass
                    break
