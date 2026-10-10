"""Network: всё сетевое MERL1N в одном модуле (Wizard API).

Секции:
  NETINFO — интерфейсы, STUN, classify_nat, TURN, брокеры (бывший netinfo.py).
  LINK    — UDP-сокет + reader + Router-сигналинг + sessions + challenge.
  PAIRING — FSM PairFlow + /pair + request()/mirror() (бывший pairing_mod.py).

Команды мода network:
  /connect /links /disconnect /link_cancel /forget (транспорт)
  /pair (сопряжение, вариант PairFlow)
  /nics (выбор интерфейса для diag; сам diag живёт в diag_mod и зовёт netinfo_*)

diag_mod остаётся отдельным, но импорт netinfo меняет на network:
  from modules import network -> network.classify_nat / stun_query / ...
MOD_NAMES: modules.network вместо modules.pairing_mod.
"""
import asyncio
import ipaddress
import json
import random
import socket
import struct
import time

from core.core import log
from core.wizard import State, StatesGroup, Wizard

_logger = log("network")

wizard = Wizard.reg_mod("network")

COOKIE = 0x2112A442

HELLO = b"MLN-HELLO-v1:"
WELCOME = b"MLN-WELCOME-v1:"
PING = b"MLN-PING-v1:"
PONG = b"MLN-PONG-v1:"
ENV = b"MLN-ENV-v1:"

STUN_HOST = "stun.sipnet.ru"
STUN_PORT = 3478
WINDOW = 12
KEEPALIVE = 15
INVITE_RESEND = 2.0
ACCEPT_TIMEOUT = 120.0


# ==================== NETINFO (бывший netinfo.py) ====================


# ==================== NETINFO ====================

QUADS = [
    {"prim": ('217.0.1.57', 3478), "sec": ('217.0.1.58', 3478)},
    {"prim": ('85.214.119.212', 3478), "sec": ('81.169.176.31', 3478)},
    {"prim": ('213.140.209.236', 3478), "sec": ('213.140.209.237', 3478)},
    {"prim": ('185.67.224.58', 3478), "sec": ('185.67.224.59', 3478)},
    {"prim": ('109.235.234.65', 3478), "sec": ('109.235.234.125', 3478)},
    {"prim": ('193.43.148.37', 3478), "sec": ('193.43.148.38', 3478)},
    {"prim": ('216.228.192.76', 3478), "sec": ('216.228.192.77', 3478)},
    {"prim": ('54.173.127.164', 3478), "sec": ('54.173.127.165', 3478)},
    {"prim": ('94.103.99.223', 3478), "sec": ('94.103.99.224', 3478)},
    {"prim": ('138.201.243.186', 3478), "sec": ('138.201.243.187', 3478)},
    {"prim": ('188.64.120.28', 3478), "sec": ('188.64.120.27', 3478)},
    {"prim": ('77.237.51.83', 3478), "sec": ('77.237.51.84', 3478)},
    {"prim": ('194.140.246.192', 3478), "sec": ('91.215.4.139', 3478)},
    {"prim": ('178.33.166.29', 3478), "sec": ('91.121.210.25', 3478)},
    {"prim": ('88.86.102.51', 3478), "sec": ('88.86.102.52', 3478)},
    {"prim": ('91.205.60.185', 3478), "sec": ('91.205.60.139', 3478)},
    {"prim": ('188.123.97.201', 3478), "sec": ('188.123.97.202', 3478)},
    {"prim": ('136.243.202.77', 3478), "sec": ('136.243.202.78', 3478)},
    {"prim": ('89.106.220.34', 3478), "sec": ('89.106.220.35', 3478)},
    {"prim": ('212.18.0.14', 3478), "sec": ('62.245.150.225', 3478)},
]


def _is_ip(x):
    try:
        ipaddress.ip_address(x)
        return True
    except ValueError:
        return False


def _is_usable_ip(ip):
    if not _is_ip(ip):
        return False
    if ip.startswith("127.") or ip.startswith("169.254."):
        return False
    return True

# ---- интерфейсы -------------------------------------------------------------

_VIRTUAL_HINTS = ("virtual", "vpn", "loopback", "vethernet", "hyper-v",
                  "vmware", "tap-", "tun-", "docker", "wsl", "bluetooth",
                  "isatap", "teredo", "pseudo", "6to4", "lo")


def _has_virtual_hint(name):
    low = (name or "").lower()
    return any(h in low for h in _VIRTUAL_HINTS)


def list_interfaces():
    """[(name, [ipv4...], note)] — без внешних зависимостей.

    Windows: главный источник — netsh (живые idx -> дружелюбные имена),
    адреса — из PowerShell-таблицы по точному имени. socket.if_nameindex
    на Windows отдаёт 50+ мусорных ethernet_N/wireless_N без адресов —
    их добавляем только если вдруг нет netsh (fallback).
    Unix: if_nameindex + ip/ifconfig как раньше.
    """
    import platform
    if platform.system() == "Windows":
        return _list_interfaces_windows()
    try:
        names = [n for _i, n in socket.if_nameindex()]
    except Exception:
        names = []
    out = []
    for name in sorted(names, key=lambda n: (_has_virtual_hint(n), n.lower())):
        addrs = _iface_ipv4(name)
        if not addrs:
            addrs = _psutil_ipv4(name)
        note = "адреса: " + ", ".join(addrs) if addrs else "без IPv4"
        out.append((name, addrs, note))
    return out


def _list_interfaces_windows():
    out = []
    try:
        itab = _win_ifindex_table() or {}
    except Exception:
        itab = {}
    try:
        pstab = _ipv4_via_powershell() or {}
    except Exception:
        pstab = {}
    seen = set()
    for idx in sorted(itab):
        name = itab[idx]
        if not name or name in seen:
            continue
        seen.add(name)
        addrs = list((pstab.get(name) or []))
        if not addrs:
            try:
                addrs = list(_iface_ipv4(name))
            except Exception:
                addrs = []
        note = "адреса: " + ", ".join(addrs) if addrs else "без IPv4"
        out.append((name, addrs, note))
    if out:
        out.sort(key=lambda t: (_has_virtual_hint(t[0]), t[0].lower()))
        return out
    # fallback: старый путь через сокеты
    try:
        names = [n for _i, n in socket.if_nameindex()]
    except Exception:
        names = []
    for name in sorted(names, key=lambda n: (_has_virtual_hint(n), n.lower())):
        addrs = _iface_ipv4(name)
        if not addrs:
            addrs = _psutil_ipv4(name)
        note = "адреса: " + ", ".join(addrs) if addrs else "без IPv4"
        out.append((name, addrs, note))
    return out


def _run(cmd, timeout=10):
    """Запустить команду, вернуть stdout str или None (если нет/таймаут/ошибка).

    PowerShell на русской Windows пишет в OEM (CP866) — text=True с utf-8
    даёт кракозябры. Поэтому всегда читаем байты и перебираем кодировки.
    """
    import subprocess
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if p.returncode != 0:
            return None
        raw = p.stdout or b""
        for enc in ("utf-8", "cp866", "cp1251"):
            try:
                out = raw.decode(enc)
                if out.strip():
                    return out
            except Exception:
                continue
        return raw.decode("utf-8", "replace")
    except Exception:
        return None


def _ipv4_via_ipcmd(name):
    """`ip -o -4 addr` — Linux, Android/Termux, macOS с iproute2."""
    found = set()
    out = _run(["ip", "-o", "-4", "addr"])
    if not out:
        return found
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] == name:
            ip = parts[3].split("/")[0]
            if _is_ip(ip):
                found.add(ip)
    return found


def _ipv4_via_ifconfig(name):
    """`ifconfig <name>` / `ipconfig getifaddr` — macOS/BSD без iproute2."""
    import platform
    found = set()
    if platform.system() == "Darwin":
        out = _run(["ipconfig", "getifaddr", name])
        if out:
            ip = out.strip()
            if _is_ip(ip):
                found.add(ip)
        if found:
            return found
    out = _run(["ifconfig", name])
    if not out:
        return found
    for line in out.splitlines():
        parts = line.split()
        for i, tok in enumerate(parts[:-1]):
            if tok == "inet":
                ip = parts[i + 1]
                if _is_ip(ip) and not ip.startswith("127."):
                    found.add(ip)
    return found


_WIN_PS_GET_NETIP = ("Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                    "Where-Object { $_.IPAddress -and $_.IPAddress -notlike '127.*' } | "
                    "ForEach-Object { \"$($_.InterfaceAlias)|$($_.IPAddress)\" }")


def _ipv4_via_powershell():
    """Windows: Get-NetIPConfiguration через PowerShell (stdlib-only сборка).

    -> dict {alias: [ipv4,...]} | None (если PowerShell недоступен).
    """
    out = _run(["powershell", "-NoProfile", "-NonInteractive",
                "-Command", _WIN_PS_GET_NETIP], timeout=30)
    if out is None:
        return None
    table = {}
    for line in out.splitlines():
        line = line.strip()
        if "|" not in line:
            continue
        alias, _, ip = line.partition("|")
        alias, ip = alias.strip(), ip.strip()
        if alias and _is_usable_ip(ip):
            table.setdefault(alias, []).append(ip)
    return table or None


_HOST_ADDRS_CACHE = {"t": None}


def _host_ipv4_addrs():
    """Все IPv4 хоста (getaddrinfo localhost + hostname с AI_ADDRCONFIG)."""
    if _HOST_ADDRS_CACHE["t"] is not None:
        return _HOST_ADDRS_CACHE["t"]
    ips = set()
    for host in ("localhost", socket.gethostname()):
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET,
                                       socket.SOCK_DGRAM, 0,
                                       socket.AI_ADDRCONFIG)
        except Exception:
            continue
        for _fam, _type, _proto, _canon, sa in infos:
            if _is_ip(sa[0]):
                ips.add(sa[0])
    _HOST_ADDRS_CACHE["t"] = sorted(ips)
    return _HOST_ADDRS_CACHE["t"]


def _iface_route_probe(addrs):
    """Какому из IP принадлежит маршрут по умолчанию (UDP-connect трюк).

    Раньше был blackhole 240.0.0.1 — на части Windows он не выбирает
    маршрут и getsockname отдаёт 0.0.0.0/None. Берём обычный публичный
    UDP-адрес без отправки пакета: connect() только выбирает маршрут.
    """
    nonlo = [a for a in addrs if not a.startswith("127.")]
    if not nonlo:
        return None
    s = None
    for dst in (("8.8.8.8", 80), ("1.1.1.1", 80)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(dst)   # пакет не уходит, только выбор маршрута
            ip = s.getsockname()[0]
            if ip and not ip.startswith("0.") and not ip.startswith("127."):
                return ip
        except Exception:
            pass
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
            s = None
    return None


def _ipv4_via_getaddrinfo(name):
    """Нативный socket-only путь (Windows без psutil / Unix без iproute2).

    getaddrinfo даёт все IPv4 хоста, но НЕ раскладывает их по NIC. Поэтому:
      * loopback — возвращаем 127.0.0.1;
      * интерфейс, которому принадлежит маршрут по умолчанию — этот адрес;
      * если у имени есть индекс и адрес ровно один — считаем его принадлежащим.
    Ошибочная атрибуция здесь допустима: дальше идёт STUN-проб, который
    отсеет неверный bind (alive=False), а diag просто покажет «не отвечает».
    """
    low = (name or "").lower()
    if low in ("lo", "loopback") or low.startswith("loopback"):
        return ["127.0.0.1"]
    addrs = _host_ipv4_addrs()
    if not addrs:
        return []
    route_ip = _iface_route_probe(addrs)
    if route_ip:
        try:
            has_idx = socket.if_nametoindex(name) > 0
        except Exception:
            has_idx = False
        if has_idx and len(addrs) == 1:
            return list(addrs)          # единственный непонятный кому NIC = он
        if route_ip and name.lower() in ("ethernet", "wi-fi", "wifi",
                                         "wlan0", "eth0", "en0", "default"):
            return [route_ip]           # заведомо «дефолтный» никнейм
    return []


_IFACE_CACHE = {}


def _alias_matches_ifindex(alias, ifname, idx):
    """Связать дружелюбный алиас PowerShell с техническим именем сокета.

    Не используется напрямую: точный маппинг даёт _win_ifindex_table()
    через netsh (idx -> дружелюбное имя). Оставлен как fallback-эвристика.
    """
    low_a, low_n = (alias or "").lower(), (ifname or "").lower()
    is_eth = low_n.startswith("ethernet_")
    is_wl = low_n.startswith("wireless_")
    if not (is_eth or is_wl):
        return False
    if is_wl and any(k in low_a for k in ("wi-fi", "wifi", "wlan", "wireless", "беспровод")):
        return True
    if is_eth and any(k in low_a for k in ("ethernet", "eth", "lan")):
        return True
    return False


_WIN_IFINDEX_TABLE = {"t": None}


def _win_ifindex_table():
    """{ifIndex int: дружелюбное имя} через netsh (OEM-кодировка)."""
    if _WIN_IFINDEX_TABLE["t"] is not None:
        return _WIN_IFINDEX_TABLE["t"] or None
    import subprocess
    table = {}
    try:
        p = subprocess.run(["netsh", "interface", "ipv4", "show", "interfaces"],
                           capture_output=True, timeout=15)
        raw = p.stdout or b""
        out = ""
        for enc in ("cp866", "cp1251", "utf-8"):
            try:
                out = raw.decode(enc)
                if out.strip():
                    break
            except Exception:
                continue
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].isdigit():
                try:
                    table[int(parts[0])] = " ".join(parts[4:])
                except Exception:
                    pass
    except Exception:
        pass
    _WIN_IFINDEX_TABLE["t"] = table or False
    return table or None


def _default_ps_alias(table):
    """Алиас интерфейса дефолтного маршрута (для fallback по имени)."""
    try:
        route_ip = _iface_route_probe(_host_ipv4_addrs())
    except Exception:
        return None
    if not route_ip:
        return None
    for alias, ips in (table or {}).items():
        if route_ip in (ips or []):
            return alias
    return None


def _iface_ipv4(name):
    """IPv4-адреса интерфейса без внешних либ, кроссплатформенно.

    Порядок: native getaddrinfo -> (Windows: PowerShell Get-NetIPConfiguration)
    -> (Unix: `ip -o -4 addr`, `ifconfig`/`ipconfig getifaddr`) -> psutil.
    Результаты кэшируются на процесс. Ошибки subprocess подавлены — раньше на
    Windows shell-вызов `ip` сыпал «Системе не удается найти указанный путь».
    """
    import platform
    key = (platform.system(), name)
    cached = _IFACE_CACHE.get(key)
    if cached is not None:
        return cached
    found = set()
    system = platform.system()
    if system == "Windows":
        found = set(_ipv4_via_getaddrinfo(name))
        if not found:
            table = _WIN_IPV4_TABLE.get("t")
            if table is None:
                table = _ipv4_via_powershell()
                _WIN_IPV4_TABLE["t"] = table if table else False
            if table:
                found.update(table.get(name, []))
                if not found:
                    # socket.if_nameindex отдаёт ethernet_N/wireless_N,
                    # PowerShell — дружелюбные алиасы. Точный маппинг:
                    # netsh idx -> имя, затем имя -> адреса из таблицы.
                    try:
                        idx = socket.if_nametoindex(name)
                    except Exception:
                        idx = None
                    if idx is not None:
                        friendly = None
                        try:
                            itab = _win_ifindex_table()
                            friendly = (itab or {}).get(idx)
                        except Exception:
                            friendly = None
                        if friendly and friendly in table:
                            found.update(table.get(friendly, []))
                        if not found:
                            for alias, ips in table.items():
                                if _alias_matches_ifindex(alias, name, idx):
                                    found.update(ips)
                                    break
                if not found:
                    # дефолтный интерфейс по маршруту — отдать его адреса
                    # даже если имя не совпало.
                    route_ip = _iface_route_probe(_host_ipv4_addrs())
                    if route_ip:
                        for alias, ips in table.items():
                            if route_ip in ips:
                                found.update(ips)
                                break
    else:
        found = set(_ipv4_via_ipcmd(name))
        if not found:
            found = set(_ipv4_via_ifconfig(name))
        if not found:
            found = set(_ipv4_via_getaddrinfo(name))
    res = sorted(found)
    if not res:
        ps = _psutil_ipv4(name)
        if ps:
            res = ps
    if not res:
        low = (name or "").lower()
        if low in ("lo", "loopback") or low.startswith("loopback"):
            res = ["127.0.0.1"]
    _IFACE_CACHE[key] = res
    return res


# кэш таблицы Windows-адресов на процесс (сбрасывать незачем — список NIC
# меняется редко; при провале храним False, чтобы не дёргать powershell в цикле)
_WIN_IPV4_TABLE = {"t": None}


def _psutil_ipv4(name):
    # Динамический импорт: psutil опционален, его нет в .pzdc/APK.
    # importlib.import_module Pylance не резолвит статически -> нет warning.
    try:
        import importlib
        psutil = importlib.import_module("psutil")
        addrs = psutil.net_if_addrs().get(name) or []
        return sorted({a.address for a in addrs if a.family == socket.AF_INET})
    except Exception:
        return []


def default_route_iface():
    """Имя «основного» интерфейса эвристикой: локальный IP дефолтного пути."""
    ip = default_local_ip()
    if ip == "?":
        return None
    for name, addrs, _n in list_interfaces():
        if ip in addrs:
            return name
    return None


def default_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "?"


# ---- STUN -------------------------------------------------------------------

def mk_binding_request(tran=None, change_ip=False, change_port=False):
    if tran is None:
        tran = bytes(random.getrandbits(8) for _ in range(12))
    msg = (struct.pack("!HHI", 0x0001, 0, COOKIE) + tran)
    if change_ip or change_port:
        # RFC 5389 CHANGE-REQUEST: value = change_ip<<2 | change_port<<1
        val = (0x04 if change_ip else 0) | (0x02 if change_port else 0)
        msg += struct.pack("!HHI", 0x0003, 4, val)
        # пересчитать длину в заголовке
        msg = struct.pack("!HHI", 0x0001, len(msg) - 20, COOKIE) + msg[20:]
    return msg, tran


_ATTR_XOR_MAPPED = 0x0020
_ATTR_MAPPED = 0x0001
_ATTR_CHANGED = 0x0005
_ATTR_SOURCE = 0x0004


def parse_stun(data, tran=None):
    """-> (ext_ip, ext_port, changed_ip|None, changed_port|None) | None."""
    if len(data) < 20:
        return None
    mt, ln = struct.unpack("!HH", data[:4])
    if mt != 0x0101:
        return None
    if tran is not None and data[8:20] != tran:
        return None
    pos, end = 20, min(20 + ln, len(data))
    ext = None
    changed = (None, None)
    while pos + 4 <= end:
        at, al = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        v = data[pos:pos + al] if pos + al <= len(data) else b""
        pos += (al + 3) & ~3
        if at == _ATTR_XOR_MAPPED and al >= 8 and v[1] == 0x01:
            port = struct.unpack("!H", v[2:4])[0] ^ COOKIE >> 16
            ip = socket.inet_ntoa(struct.pack("!I",
                     struct.unpack("!I", v[4:8])[0] ^ COOKIE))
            ext = (ip, port)
        elif at == _ATTR_MAPPED and al >= 8 and v[1] == 0x01:
            ext = (socket.inet_ntoa(v[4:8]), struct.unpack("!H", v[2:4])[0])
        elif at == _ATTR_CHANGED and al >= 8 and v[1] == 0x01:
            changed = (socket.inet_ntoa(v[4:8]),
                       struct.unpack("!H", v[2:4])[0])
    if ext is None:
        return None
    return ext[0], ext[1], changed[0], changed[1]


def stun_query(ip, port, timeout=2.5, sock=None, bind_addr=None,
               change_ip=False, change_port=False):
    """Один Binding Request. ((ext_ip,ext_port,changed_ip,changed_port)|None, ms)."""
    req, tran = mk_binding_request(change_ip=change_ip, change_port=change_port)
    own = sock is None
    t0 = time.monotonic()
    try:
        if own:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if bind_addr:
                sock.bind((bind_addr, 0))
            else:
                sock.bind(("", 0))
        sock.settimeout(timeout)
        try:
            sock.sendto(req, (ip, port))
        except Exception:
            return None, int((time.monotonic() - t0) * 1000)
        deadline = t0 + timeout
        while True:
            try:
                data, src = sock.recvfrom(2048)
            except (socket.timeout, OSError):
                return None, int((time.monotonic() - t0) * 1000)
            r = parse_stun(data, tran)
            if r:
                return r, int((time.monotonic() - t0) * 1000)
            if time.monotonic() > deadline:
                return None, int((time.monotonic() - t0) * 1000)
    finally:
        if own:
            try:
                sock.close()
            except Exception:
                pass


def stun_probe_iface(name, servers, timeout=2.5):
    """Мягкий проб NIC без захвата: bind к первому IPv4 интерфейса -> STUN.

    -> (alive: bool, ext: (ip,port)|None, local_addr|None)
    """
    addrs = _iface_ipv4(name) or _psutil_ipv4(name)
    if not addrs:
        # интерфейс без адреса определить нельзя — считаем мёртвым
        return False, None, None
    ip4 = addrs[0]
    for host, port in servers:
        sip = resolve(host)
        if not sip:
            continue
        r, _ms = stun_query(sip, port, timeout=timeout, bind_addr=ip4)
        if r:
            return True, (r[0], r[1]), ip4
    return False, None, ip4


# ---- классификатор NAT (замена aionetiface.nic.nat.nat_utils) ----------------

NAT_OPEN, NAT_UDP_FW, NAT_FULL_CONE, NAT_RESTRICT, \
    NAT_RESTRICT_PORT, NAT_SYMMETRIC, NAT_BLOCKED = range(1, 8)

DELTA_NA, DELTA_EQUAL, DELTA_PRESERV, DELTA_INDEP, \
    DELTA_DEPENDENT, DELTA_RANDOM = range(1, 7)


def _pick_live_pair(servers, timeout=2.5, need=2):
    """Первые need живых (host,port,ip) из списка: DNS + 1 STUN-проба с ретраем."""
    live = []
    for host, port in servers:
        ip = resolve(host)
        if not ip:
            continue
        r, _ms = stun_query(ip, port, timeout=timeout)
        if r is None:
            r, _ms = stun_query(ip, port, timeout=timeout)
        if r is not None:
            live.append((host, port, ip))
            if len(live) >= need:
                break
    return live


def _self_inbound_test(s1, ext1, timeout=3.0):
    """Входящее с незнакомого адреса: второй сокет шлёт на ext первого.

    Аналог теста 2 из aionetiface (ответ с secondary-адреса), но без
    secondary: вместо него свой второй сокет. Если s1 получил пакет,
    пришедший снаружи без предварительного исходящего туда -> фильтр
    пускает всех (FULL_CONE). Тишина -> RESTRICTED.
    Возвращает True/False/None (None = не удалось провести).
    """
    s2 = None
    try:
        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s2.bind(("", 0))
        probe = b"MLN-INBOUND-PROBE:" + bytes(random.getrandbits(8) for _ in range(8))
        try:
            s2.sendto(probe, ext1)
        except Exception:
            return None
        s1.settimeout(timeout)
        deadline = time.monotonic() + timeout
        while True:
            try:
                data, _src = s1.recvfrom(2048)
            except (socket.timeout, OSError):
                return False
            if data == probe:
                return True
            if time.monotonic() > deadline:
                return False
    except Exception:
        return None
    finally:
        if s2 is not None:
            try:
                s2.close()
            except Exception:
                pass


def _live_quad(timeout=2.5):
    """Первая живая (prim, sec) пара из stun_pool: обе отвечают."""
    for q in QUADS:
        ph, pp = q["prim"]
        sh, sp = q["sec"]
        pip = resolve(ph)
        sip = resolve(sh)
        if not pip or not sip:
            continue
        r1, _m1 = stun_query(pip, pp, timeout=timeout)
        if r1 is None:
            continue
        r2, _m2 = stun_query(sip, sp, timeout=timeout)
        if r2 is None:
            continue
        return (ph, pp, pip), (sh, sp, sip)
    return None


def classify_nat(server, alt, timeout=2.5, attempts=2, pool=None):
    """Схема aionetiface NAT_TEST_SCHEMA на stdlib + пул primary/secondary.

    Тест 1: s1 -> prim (ждём оттуда же) -> e1.
    Тест 3: s1 -> sec (другой IP того же сервера) -> e3.
      e3 == e1 -> non-symmetric (маппинг переиспользуется).
      e3 != e1 -> SYMMETRIC.
    Тесты 2/4 (ответ с чужого) требуют CHANGE-REQUEST — серверы RFC 5389
    его не поддерживают. Вместо них self-inbound (свой второй сокет
    шлёт на ext): дошло -> FULL_CONE, тишина -> RESTRICTED.
    server/alt — fallback если пул stun_pool недоступен.
    """
    quad = _live_quad(timeout=timeout)
    if quad is None:
        # fallback: старая логика на server/alt + pool живых
        return _classify_legacy(server, alt, timeout, attempts, pool)
    (ph, pp, pip), (sh2, sp2, sip2) = quad
    sh, sp, sip = ph, pp, pip
    ah, ap, aip = sh2, sp2, sip2
    socks = []
    try:
        for _ in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("", 0))
            socks.append(s)
        s1, s2 = socks
        l1, l2 = s1.getsockname(), s2.getsockname()

        def q(sock, ip, port):
            for _a in range(attempts):
                r, _ms = stun_query(ip, port, timeout=timeout, sock=sock)
                if r:
                    return r
            return None

        # Тест 1: prim -> e1
        r1 = q(s1, sip, sp)
        if r1 is None:
            return {"type": NAT_BLOCKED, "delta": {"type": DELTA_NA},
                    "note": "UDP blocked"}
        e1 = (r1[0], r1[1])
        # delta: второй сокет туда же
        r2 = q(s2, sip, sp)
        e2 = (r2[0], r2[1]) if r2 else None
        if e2 is None:
            delta = DELTA_NA
        elif e2 == (l2[0], l2[1]):
            delta = DELTA_EQUAL
        elif abs(e2[1] - l2[1]) <= 10:
            delta = DELTA_PRESERV
        else:
            delta = DELTA_INDEP
        # Тест 3: тот же сокет -> sec IP. Сравнение с e1.
        r3 = q(s1, aip, ap)
        if r3 is None:
            sym = None
        else:
            sym = (r3[0], r3[1]) != e1
        if sym and delta == DELTA_INDEP:
            delta = DELTA_DEPENDENT

        nat_type = NAT_FULL_CONE
        filter_note = "no-filter-test"
        if e1 == (l1[0], l1[1]):
            nat_type = NAT_OPEN
        elif sym:
            nat_type = NAT_SYMMETRIC
        elif sym is None:
            nat_type = NAT_RESTRICT_PORT
            filter_note = "sec silent: cone, подтип неизвестен"
        else:
            inbound = _self_inbound_test(s1, e1, timeout=3.0)
            if inbound is True:
                nat_type = NAT_FULL_CONE
                filter_note = "self-inbound answered -> FULL_CONE"
            elif inbound is False:
                nat_type = NAT_RESTRICT
                filter_note = "self-inbound silent -> RESTRICT"
            else:
                nat_type = NAT_RESTRICT_PORT
                filter_note = "self-inbound inconclusive"

        return {
            "type": nat_type,
            "delta": {"type": delta},
            "is_open": nat_type == NAT_OPEN,
            "can_predict": nat_type in (NAT_FULL_CONE, NAT_RESTRICT,
                                        NAT_RESTRICT_PORT) and not sym,
            "is_hard": nat_type == NAT_SYMMETRIC,
            "ext": "%s:%d" % e1,
            "note": "quad %s:%d/%s:%d; %s" % (sh, sp, ah, ap, filter_note),
        }
    finally:
        for s in socks:
            try:
                s.close()
            except Exception:
                pass


def _classify_legacy(server, alt, timeout, attempts, pool):
    sh, sp = server
    # основной сервер: 1 проба + ретрай, иначе замена из pool
    sip = resolve(sh)
    ok_main = False
    if sip:
        r0, _m0 = stun_query(sip, sp, timeout=timeout)
        if r0 is None:
            r0, _m0 = stun_query(sip, sp, timeout=timeout)
        ok_main = r0 is not None
    if not ok_main:
        if pool:
            cand = [c for c in _pick_live_pair(pool, timeout=timeout, need=1)]
            # не берем alt как замену основному чтобы пара была разной
            cand = [c for c in cand if (c[0], c[1]) != (alt[0], alt[1])] or _pick_live_pair(
                pool, timeout=timeout, need=1)
            if cand:
                sh, sp, sip = cand[0]
                ok_main = True
        if not ok_main:
            return {"type": NAT_BLOCKED, "delta": {"type": DELTA_NA},
                    "note": "no live STUN (main %s silent)" % sh}
    socks = []
    try:
        for _ in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("", 0))
            socks.append(s)
        s1, s2 = socks
        l1, l2 = s1.getsockname(), s2.getsockname()

        def q(sock, ip, port):
            for _a in range(attempts):
                r, _ms = stun_query(ip, port, timeout=timeout, sock=sock)
                if r:
                    return r
            return None

        r1 = q(s1, sip, sp)
        if r1 is None:
            return {"type": NAT_BLOCKED, "delta": {"type": DELTA_NA},
                    "note": "UDP blocked"}
        e1 = (r1[0], r1[1])
        r2 = q(s2, sip, sp)
        e2 = (r2[0], r2[1]) if r2 else None

        # delta: одинаковый ли ext у двух сокетов одного хоста?
        if e2 is None:
            delta = DELTA_NA
        elif e2 == (l2[0], l2[1]):
            delta = DELTA_EQUAL
        elif abs(e2[1] - l2[1]) <= 10:
            delta = DELTA_PRESERV
        else:
            delta = DELTA_INDEP  # уточним ниже тестом на другой dst

        # симметричность: тот же сокет, но другой сервер.
        # alt может молчать — ищем живую замену из pool (не равную основному).
        ah, ap = alt
        aip = resolve(ah) if not _is_ip(ah) else ah
        sym = None
        r3 = q(s1, aip, ap) if aip else None
        if r3 is None and pool:
            for hh, pp, iip in _pick_live_pair(pool, timeout=timeout, need=3):
                if (hh, pp) == (sh, sp):
                    continue
                r3 = q(s1, iip, pp)
                if r3 is not None:
                    ah, ap, aip = hh, pp, iip
                    break
        if r3 is None:
            sym = None
        else:
            sym = (r3[0], r3[1]) != e1
        if sym and delta == DELTA_INDEP:
            delta = DELTA_DEPENDENT

        nat_type = NAT_FULL_CONE
        filter_note = "no-filter-test"
        if e1 == (l1[0], l1[1]):
            nat_type = NAT_OPEN
        elif sym:
            nat_type = NAT_SYMMETRIC
        else:
            # cone, но какой? CHANGE-REQUEST мёртв (серверы RFC 5389
            # secondary не отдают). Вместо него self-inbound: второй
            # сокет шлёт на ext первого снаружи. Дошло -> FULL_CONE.
            inbound = _self_inbound_test(s1, e1, timeout=3.0)
            if inbound is True:
                nat_type = NAT_FULL_CONE
                filter_note = "self-inbound answered -> FULL_CONE"
            elif inbound is False:
                # порт/IP различить нечем без secondary: честно
                # называем RESTRICT (фильтр есть), для панча разницы нет.
                nat_type = NAT_RESTRICT
                filter_note = "self-inbound silent -> RESTRICT (подтип портом/IP неразличим)"
            else:
                nat_type = NAT_RESTRICT_PORT
                filter_note = ("self-inbound inconclusive: cone, подтип неизвестен "
                               "(считаем RESTRICT_PORT для панча)")

        return {
            "type": nat_type,
            "delta": {"type": delta},
            "is_open": nat_type == NAT_OPEN,
            "can_predict": nat_type in (NAT_FULL_CONE, NAT_RESTRICT,
                                        NAT_RESTRICT_PORT) and not sym,
            "is_hard": nat_type == NAT_SYMMETRIC,
            "ext": "%s:%d" % e1,
            "note": "pair %s:%d/%s:%d; %s" % (sh, sp, ah, ap, filter_note),
        }
    finally:
        for s in socks:
            try:
                s.close()
            except Exception:
                pass


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


# ---- TURN (замена warpgate.traversal.plugins.turn) ---------------------------

_TURN_ALLOCATE = 0x0003
_TURN_SUCCESS = 0x0103
_TURN_ERR = 0x0111
_TURN_ATTR_XOR_RELAY = 0x0016
_TURN_ATTR_LIFETIME = 0x000C
_SOFTWARE = b"MERL1N-diag"


def turn_allocate(server, timeout=4.0, user="diag", secret="diag"):
    """RFC-5766 Allocate без аутентификации.

    Возвращает dict(status, relay|None, note). Статусы:
      'alloc'  —Allocate Success (relay получен),
      'challenge' — 401: сервер жив и понимает TURN (дальше нужен реальный credential),
      'fail'   — нет ответа / ошибка.
    """
    host, port = server
    ip = resolve(host) if not _is_ip(host) else host
    if not ip:
        return {"status": "fail", "relay": None, "note": "DNS fail"}
    tran = bytes(random.getrandbits(8) for _ in range(12))

    def attrs(extra=b"", cred=None):
        a = struct.pack("!HH", 0x0003, 4) + b"\x01\x00\x00\x00"     # REQUESTED-TRANSPORT UDP
        a += struct.pack("!HH", 0x8004, len(_SOFTWARE)) + _SOFTWARE  # SOFTWARE
        a += extra
        if cred:
            u, p = cred
            a += struct.pack("!HH", 0x0006, len(u)) + u.encode()     # USERNAME
            realm = p[0].encode() if isinstance(p, tuple) else b""
            nonce = p[1].encode() if isinstance(p, tuple) and len(p) > 1 else b""
            if realm:
                a += struct.pack("!HH", 0x0014, len(realm)) + realm
            if nonce:
                a += struct.pack("!HH", 0x0015, len(nonce)) + nonce
        return a

    def msg(mtype, body):
        return (struct.pack("!HHI", mtype, len(body), COOKIE) + tran + body)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", 0))
        s.settimeout(timeout)
        s.sendto(msg(_TURN_ALLOCATE, attrs()), (ip, port))
        resp = _recv_stun(s, tran, timeout)
        if resp is None:
            return {"status": "fail", "relay": None, "note": "no response"}
        mt, body = resp
        if mt == _TURN_ERR:
            code = _attr_int(body, 0x0009)
            realm = _attr_str(body, 0x0014)
            nonce = _attr_str(body, 0x0015)
            if code == 401 and realm is not None:
                # повторим с credential (long-term MD5 ключ, RFC-5389)
                import hashlib
                key = hashlib.md5(("%s:%s:%s" % (user, realm, secret)).encode()).hexdigest().encode()
                a = attrs(cred=(user, (realm, nonce)))
                # MESSAGE-INTEGRITY + FINGERPRINT упрощённо не шлём:
                # многие серверы на этом месте всё равно дают 403 — фиксируем достижимость
                s.sendto(msg(_TURN_ALLOCATE, a), (ip, port))
                resp2 = _recv_stun(s, tran, timeout)
                if resp2 is None:
                    return {"status": "fail", "relay": None, "note": "401 then silence"}
                mt2, body2 = resp2
                if mt2 == _TURN_SUCCESS:
                    return {"status": "alloc", "relay": _xor_relay(body2),
                            "note": "auth OK"}
                code2 = _attr_int(body2, 0x0009) or 0
                return {"status": "challenge", "relay": None,
                        "note": "server alive, err=%s (нужен реальный credential)" % code2}
            return {"status": "challenge", "relay": None,
                    "note": "err=%s" % (code or "?")}
        if mt == _TURN_SUCCESS:
            return {"status": "alloc", "relay": _xor_relay(body), "note": "OK"}
        return {"status": "fail", "relay": None, "note": "pkt 0x%x" % mt}
    except OSError as e:
        return {"status": "fail", "relay": None, "note": "%s" % e}
    finally:
        try:
            s.close()
        except Exception:
            pass


def _recv_stun(sock, tran, timeout):
    deadline = time.monotonic() + timeout
    while True:
        rem = max(0.1, deadline - time.monotonic())
        sock.settimeout(rem)
        try:
            data, _src = sock.recvfrom(2048)
        except (socket.timeout, OSError):
            return None
        if len(data) >= 20 and data[8:20] == tran:
            mt, ln = struct.unpack("!HH", data[:4])
            return mt, data[20:20 + ln]


def _attr_iter(body):
    pos = 0
    while pos + 4 <= len(body):
        at, al = struct.unpack("!HH", body[pos:pos + 4])
        pos += 4
        yield at, body[pos:pos + al]
        pos += (al + 3) & ~3


def _attr_int(body, want):
    for at, v in _attr_iter(body):
        if at == want and len(v) >= 4:
            return struct.unpack("!I", v[:4])[0]
    return None


def _attr_str(body, want):
    for at, v in _attr_iter(body):
        if at == want:
            return v.decode("utf-8", "replace")
    return None


def _xor_relay(body):
    for at, v in _attr_iter(body):
        if at == _TURN_ATTR_XOR_RELAY and len(v) >= 4 and v[1] == 0x01:
            port = struct.unpack("!H", v[2:4])[0] ^ COOKIE >> 16
            ip = socket.inet_ntoa(struct.pack("!I",
                     struct.unpack("!I", v[4:8])[0] ^ COOKIE))
            return "%s:%d" % (ip, port)
    return None


# ---- брокеры (замена sidewire.utils.get_mqtt_server_list) ---------------------

DEFAULT_BROKERS = [("broker.emqx.io", 1883), ("test.mosquitto.org", 1883)]

# статический fallback-список публичных MQTT-брокеров (stdlib-only сборка)
_STATIC_BROKERS = [
    ("broker.emqx.io", 1883), ("broker.hivemq.com", 1883),
    ("test.mosquitto.org", 1883), ("mqtt.eclipseprojects.io", 1883),
]


def get_mqtt_server_list():
    """{af: {host: {"port": int}}} в формате sidewire — но из своего конфига/DNS.

    Порядок: ~/.merlin/brokers.json -> встроенный статический список.
    """
    import json
    import os
    cfg = os.path.join(os.path.expanduser("~"), ".merlin", "brokers.json")
    try:
        with open(cfg, "r", encoding="utf-8") as f:
            data = json.load(f)
        out = {}
        for rec in data.get("brokers", []):
            h, p = rec.get("host"), int(rec.get("port", 1883))
            if not h:
                continue
            af = "AF_INET6" if ":" in h else "AF_INET"
            out.setdefault(af, {})[h] = {"port": p}
        if out:
            return out
    except Exception:
        pass
    return {"AF_INET": {h: {"port": p} for h, p in _STATIC_BROKERS}}


def broker_list_fallback():
    return list(DEFAULT_BROKERS)


# ==================== PAIRING (бывший pairing_mod.py) ====================

class PairFlow(StatesGroup):
    """Группа состояний сценария сопряжения."""
    ask_accept = State()
    ask_mirror = State()
    ask_name = State()
    ask_role = State()


def _pair_rid() -> str:
    import time as _t
    return str(int(_t.time()) % 10000)


async def _pair_start(ctx, fsm, pub_key: str, state, data: dict) -> None:
    fsm.data_of(pub_key).clear()
    fsm.data_of(pub_key).update(data)
    await fsm.storage.set(pub_key, state)
    fsm.touch(pub_key)


@wizard.command(command="pair", desc="сопрячься с пиром по pubkey", role="admin")
async def pair(ctx, message, fsm, pub: str):
    return await pair_request(ctx, pub, _pair_rid(), from_pub=message.pub)


async def pair_request(ctx, pub: str, rid: str = "0", from_pub: str = "") -> str:
    from core.wizard import Wizard as _Wz
    fsm = _Wz.instance().fsm
    await _pair_start(ctx, fsm, from_pub, PairFlow.ask_accept,
                      {"pub": pub, "rid": rid, "outgoing": True})
    return (f"\n=== pairing #{rid} ===\npeer pub: {pub}\n"
            f"[#{rid}] accept? [y/n]: ")


async def pair_mirror(ctx, pub: str, from_pub: str = "") -> str:
    from core.wizard import Wizard as _Wz
    fsm = _Wz.instance().fsm
    await _pair_start(ctx, fsm, from_pub, PairFlow.ask_mirror,
                      {"pub": pub, "mirror": True, "outgoing": True})
    return (f"\n=== mutual save ===\npeer {pub[:12]}... accepted you.\n"
            f"save? [y/n] (default y): ")


@wizard.text(PairFlow.ask_accept, idle=180)
async def st_accept(ctx, message, fsm_ctx):
    d = dict(fsm_ctx.get_data())
    a = message.text.strip().lower()
    if a in ("n", "no"):
        await fsm_ctx.finish()
        return f"[{d.get('rid', '?')}] rejected (offline, no link to notify)."
    await fsm_ctx.set(PairFlow.ask_name)
    return f"[{d.get('rid', '?')}] name (empty -> {d['pub'][:12]}): "


@wizard.text(PairFlow.ask_mirror, idle=180)
async def st_mirror(ctx, message, fsm_ctx):
    a = message.text.strip().lower()
    if a in ("n", "no"):
        await fsm_ctx.finish()
        return "not saved."
    d = fsm_ctx.get_data()
    d.setdefault("mirror", True)
    await fsm_ctx.set(PairFlow.ask_name)
    return f"name (empty -> {d['pub'][:12]}): "


@wizard.text(PairFlow.ask_name, idle=180)
async def st_name(ctx, message, fsm_ctx):
    d = fsm_ctx.get_data()
    d["name"] = message.text.strip() or d["pub"][:12]
    await fsm_ctx.set(PairFlow.ask_role)
    hint = "role [viewer/operator/admin] (empty -> viewer): " \
        if getattr(ctx, "kind", "") == "server" else \
        "role (empty -> viewer): "
    return hint


@wizard.text(PairFlow.ask_role, idle=180)
async def st_role(ctx, message, fsm_ctx):
    d = dict(fsm_ctx.get_data())
    role = (message.args[0].lower() if message.args else "") or "viewer"
    ctx.peers.add(d["pub"], d["name"], role)
    tail = " (offline)" if not d.get("mirror") else ""
    reply = f"saved {ctx.peers.label(d['pub'])} [{role}]{tail}"
    await fsm_ctx.finish()
    return reply


# ==================== LINK (бывший link_mod.py, переписан под Wizard) ====================

def _pub_text(x):
    if x is None:
        return ""
    if isinstance(x, (bytes, bytearray, memoryview)):
        try:
            return bytes(x).decode("utf-8", "replace").strip()
        except Exception:
            return str(x).strip()
    return str(x).strip()


def clean_pub(x):
    s = _pub_text(x)
    if s.lower().startswith("0x"):
        s = s[2:]
    return s.strip()


def norm_pub(x):
    return clean_pub(x).lower()


def short_pub(x, n=12):
    s = clean_pub(x)
    if not s:
        return "?"
    return s if len(s) <= n else s[:n] + "..."


def _verify(pub_hex, sig_hex, msg):
    try:
        from ecdsa import SECP256k1, VerifyingKey, util
        vk = VerifyingKey.from_string(bytes.fromhex(pub_hex), curve=SECP256k1)
        return vk.verify(bytes.fromhex(sig_hex), msg, sigdecode=util.sigdecode_string)
    except Exception:
        return False


def _sign(priv, msg):
    from ecdsa import util
    return priv.sign(msg, sigencode=util.sigencode_string).hex()


class Links:
    """Один UDP-сокет + reader + Router + N сессий. Живёт в ctx.links."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.sock = None
        self.lport = 0
        self.my_ext = None
        self.router = None
        self.kp = None
        self.sessions = {}
        self._reader = None
        self._stun_q = asyncio.Queue()
        self._running = False

    async def start(self):
        from aionetiface.utility.signing import Signing
        try:
            self.kp = Signing(self.ctx.keys.priv)
        except Exception as e:
            raise RuntimeError("signing wrap failed: %r" % (e,))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.setblocking(False)
        self.lport = self.sock.getsockname()[1]
        self._running = True
        self._reader = asyncio.create_task(self._udp_reader())
        ext, _note = await self.measure_ext()
        if ext:
            self.my_ext = ext
        try:
            from sidewire import Router
            self.router = Router(self.kp, msg_handler=self._sig_rx,
                                 get_time=time.time)
            await self.router.__aenter__()
        except ImportError:
            self.router = None
        except Exception as e:
            _logger.error("router start failed: %r" % (e,))
            self.router = None
        return self

    async def stop(self):
        self._running = False
        for _np, s in list(self.sessions.items()):
            for k in ("punch_task", "ka_task", "invite_task"):
                t = s.get(k)
                if t is not None and not t.done():
                    t.cancel()
        self.sessions.clear()
        if self._reader is not None:
            self._reader.cancel()
            self._reader = None
        if self.router is not None:
            try:
                await self.router.__aexit__(None, None, None)
            except Exception:
                pass
            self.router = None
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    async def measure_ext(self, tries=3, timeout=3.0):
        try:
            ip = socket.gethostbyname(STUN_HOST)
        except Exception as e:
            return None, "DNS %r" % (e,)
        loop = asyncio.get_event_loop()
        for t in range(1, tries + 1):
            while not self._stun_q.empty():
                try:
                    self._stun_q.get_nowait()
                except Exception:
                    break
            req, tran = mk_binding_request()
            try:
                await loop.sock_sendto(self.sock, req, (ip, STUN_PORT))
                deadline = time.time() + timeout
                while True:
                    remain = deadline - time.time()
                    if remain <= 0:
                        break
                    try:
                        data, _a = await asyncio.wait_for(self._stun_q.get(), remain)
                    except asyncio.TimeoutError:
                        break
                    r = parse_stun(data, tran)
                    if r:
                        return (r[0], r[1]), "ok try=%d" % t
            except Exception as e:
                if t == tries:
                    return None, "%s" % type(e).__name__
                await asyncio.sleep(0.5)
        return None, "no answer"

    try:
        _IP_CHECK = ipaddress.ip_address("127.0.0.1")
    except Exception:
        _IP_CHECK = None
    async def _udp_reader(self):
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                data, addr = await loop.sock_recvfrom(self.sock, 4096)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.05)
                continue
            try:
                await self._on_dgram(bytes(data), addr)
            except Exception as e:
                _logger.error("reader: %r" % (e,))

    async def _on_dgram(self, data, addr):
        if len(data) >= 20:
            try:
                mt, _ln = struct.unpack("!HH", data[:4])
                if mt == 0x0101 and data[4:8] == struct.pack("!I", COOKIE):
                    self._stun_q.put_nowait((data, addr))
                    return
            except Exception:
                pass
        for prefix in (HELLO, WELCOME, PING, PONG, ENV):
            if data.startswith(prefix):
                if prefix is ENV:
                    await self._rx_env(data[len(prefix):], addr)
                else:
                    await self._rx_ctrl(prefix, data[len(prefix):], addr)
                return

    async def _rx_ctrl(self, prefix, body, addr):
        try:
            parts = body.decode("utf-8", "replace").split(":", 1)
        except Exception:
            return
        sender = clean_pub(parts[0]) if parts else ""
        snorm = norm_pub(sender)
        if not snorm:
            return
        s = self.sessions.get(snorm)
        loop = asyncio.get_event_loop()
        if prefix is HELLO:
            if s is None:
                return
            s["addr"] = addr
            s["rx"] = s.get("rx", 0) + 1
            try:
                await loop.sock_sendto(
                    self.sock, WELCOME + self.ctx.keys.pub.encode(), addr)
            except Exception:
                pass
            return
        if prefix is WELCOME:
            if s is None:
                return
            s["addr"] = addr
            s["rx"] = s.get("rx", 0) + 1
            s["link_up"].set()
            return
        if prefix is PING:
            extra = parts[1] if len(parts) > 1 else "0"
            try:
                await loop.sock_sendto(
                    self.sock, PONG + self.ctx.keys.pub.encode() + b":" + extra.encode(), addr)
            except Exception:
                pass
            if s is not None:
                s["last_rx"] = time.time()
            return
        if prefix is PONG:
            if s is not None:
                s["last_rx"] = time.time()
            return

    async def _rx_env(self, body, addr):
        try:
            d = json.loads(body.decode("utf-8"))
        except Exception:
            return
        if not isinstance(d, dict):
            return
        frm = clean_pub(d.get("from", ""))
        fnorm = norm_pub(frm)
        s = self.sessions.get(fnorm)
        if s is None:
            return
        s["addr"] = addr
        s["last_rx"] = time.time()
        env = d.get("env")
        if not isinstance(env, dict):
            return
        from core.wizard import Wizard as _Wz
        try:
            await _Wz.instance().handle(
                self.ctx, {"pub": frm, "from": frm,
                           "message": {"text": (env.get("message") or {}).get("text", [])}},
                via_link=True)
        except Exception:
            pass

    async def _send_relay(self, to_pub, obj):
        if self.router is None:
            raise RuntimeError("no signaling (sidewire missing)")
        obj = dict(obj)
        obj.setdefault("nonce", "%s-%x" % (time.time(), random.getrandbits(32)))
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        pipe = await self.router.pipe(dest_pub_hex=to_pub)
        n = await pipe.send(raw)
        if not n:
            raise RuntimeError("relay send=0")

    def _sess(self, snorm, pub):
        s = self.sessions.get(snorm)
        if s is None:
            s = {"pub": pub, "norm": snorm, "state": "new",
                 "addr": None, "ext": None, "link_up": asyncio.Event(),
                 "rx": 0, "last_rx": 0.0, "punch_task": None,
                 "ka_task": None, "invite_task": None,
                 "my_nonce": None, "authed": False}
            self.sessions[snorm] = s
        return s

    def _drop(self, snorm):
        s = self.sessions.pop(snorm, None)
        if s is None:
            return
        for k in ("punch_task", "ka_task", "invite_task"):
            t = s.get(k)
            if t is not None and not t.done():
                t.cancel()

    async def _sig_rx(self, msg, sender_pubkey, queue_id, mqtt_client):
        try:
            raw = msg.encode("utf-8", "replace") if isinstance(msg, str) else bytes(msg)
        except Exception:
            return
        try:
            txt = raw.decode("utf-8", "replace")
        except Exception:
            return
        body = raw
        if len(raw) >= 4:
            try:
                (ln,) = struct.unpack("!I", raw[:4])
                if ln == len(raw) - 4:
                    body = raw[4:]
            except Exception:
                pass
        try:
            d = json.loads(body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else txt)
        except Exception:
            return
        if not isinstance(d, dict):
            return
        t = d.get("t")
        if t not in ("invite", "accept", "deny", "abort", "ready", "bye", "challenge", "proof", "relay-msg"):
            return
        sender = clean_pub(sender_pubkey)
        snorm = norm_pub(sender)
        if not snorm:
            return
        await self._on_signal(snorm, sender, d)

    async def _on_signal(self, snorm, sender, d):
        t = d.get("t")
        if t == "invite":
            await self._rx_invite(snorm, sender, d)
            return
        s = self.sessions.get(snorm)
        if t == "accept":
            if s is not None:
                s["peer_ext"] = (d.get("ext", [None, 0])[0], int(d.get("ext", [None, 0])[1] or 0))
                if s.get("accepted_ev") is not None:
                    s["accepted_ev"].set()
            return
        if t == "deny":
            if s is not None:
                s["denied"] = True
                if s.get("accepted_ev") is not None:
                    s["accepted_ev"].set()
            await self._wiz_send(sender, "пир %s отклонил линк." % short_pub(sender))
            return
        if t == "abort":
            self._drop(snorm)
            await self._wiz_send(sender, "пир %s отменил линк." % short_pub(sender))
            return
        if t == "ready":
            if s is not None and s.get("ready_ev") is not None:
                s["ready_ev"].set()
            return
        if t == "bye":
            if s is not None:
                s["link_up"].clear()
                s["addr"] = None
            await self._wiz_send(sender, "пир %s отключился." % short_pub(sender))
            return
        if t == "challenge":
            await self._rx_challenge(snorm, sender, d)
            return
        if t == "proof":
            await self._rx_proof(snorm, sender, d)
            return
        if t == "relay-msg":
            env = d.get("env")
            if isinstance(env, dict):
                from core.wizard import Wizard as _Wz
                try:
                    await _Wz.instance().handle(
                        self.ctx, {"pub": sender, "from": sender,
                                   "message": {"text": (env.get("message") or {}).get("text", [])}},
                        via_link=True)
                except Exception:
                    pass
            return

    async def _wiz_send(self, pub, text):
        try:
            from core.wizard import Wizard as _Wz
            await _Wz.instance().send(text, pub)
        except Exception:
            pass

    async def _rx_invite(self, snorm, sender, d):
        peer_ext = (d.get("ext", [None, 0])[0], int(d.get("ext", [None, 0])[1] or 0))
        s = self._sess(snorm, sender)
        if s["link_up"].is_set():
            return
        s["peer_ext"] = peer_ext
        if self.ctx.peers.known(sender):
            try:
                if not self.my_ext:
                    ext, _n = await self.measure_ext()
                    if ext:
                        self.my_ext = ext
                await self._send_relay(sender, {"t": "accept",
                    "ext": [self.my_ext[0], self.my_ext[1]] if self.my_ext else [None, 0]})
            except Exception:
                return
            asyncio.create_task(self._punch_and_auth(snorm))
            return
        try:
            await pair_request(self.ctx, sender, "net", from_pub="")
        except Exception:
            pass
        s["state"] = "wizard"

    async def _rx_challenge(self, snorm, sender, d):
        s = self.sessions.get(snorm)
        if s is None:
            return
        if not _verify(sender, d.get("sig", ""), (s.get("my_nonce") or "").encode()):
            return
        s["peer_nonce"] = d.get("nonce", "")
        try:
            sig = _sign(self.ctx.keys.priv, (s["peer_nonce"] or "").encode())
        except Exception:
            return
        try:
            await self._send_relay(sender, {"t": "proof", "sig": sig, "nonce": s.get("my_nonce", "")})
        except Exception:
            pass
        s["challenged"] = True
        if s.get("peer_authed"):
            s["authed"] = True
            if s.get("auth_ev") is not None:
                s["auth_ev"].set()

    async def _rx_proof(self, snorm, sender, d):
        s = self.sessions.get(snorm)
        if s is None:
            return
        if not _verify(sender, d.get("sig", ""), (s.get("my_nonce") or "").encode()):
            return
        s["peer_authed"] = True
        if s.get("challenged"):
            s["authed"] = True
            if s.get("auth_ev") is not None:
                s["auth_ev"].set()

    async def _punch_loop(self, snorm):
        s = self.sessions.get(snorm)
        if s is None or not s.get("peer_ext") or not s["peer_ext"][0]:
            return
        loop = asyncio.get_event_loop()
        hello = HELLO + self.ctx.keys.pub.encode()
        t_end = time.time() + WINDOW
        while time.time() < t_end and not s["link_up"].is_set():
            try:
                await loop.sock_sendto(self.sock, hello, s["peer_ext"])
            except Exception:
                break
            await asyncio.sleep(0.2)

    async def _ka_loop(self, snorm):
        loop = asyncio.get_event_loop()
        s = self.sessions.get(snorm)
        if s is None:
            return
        while self._running and s["link_up"].is_set():
            await asyncio.sleep(KEEPALIVE)
            try:
                addr = s.get("addr") or s.get("peer_ext")
                if addr and addr[0]:
                    await loop.sock_sendto(
                        self.sock, PING + self.ctx.keys.pub.encode() + b":%d" % int(time.time()), addr)
            except Exception:
                break

    async def _punch_and_auth(self, snorm):
        s = self.sessions.get(snorm)
        if s is None:
            return
        s["state"] = "punching"
        s["punch_task"] = asyncio.create_task(self._punch_loop(snorm))
        try:
            await asyncio.wait_for(s["link_up"].wait(), WINDOW + 5)
        except asyncio.TimeoutError:
            s["state"] = "failed"
            await self._wiz_send(s["pub"], "LINK FAILED к %s." % short_pub(s["pub"]))
            return
        s["state"] = "auth"
        s["my_nonce"] = "%x" % random.getrandbits(128)
        s["auth_ev"] = asyncio.Event()
        s["challenged"] = False
        s["peer_authed"] = False
        s["authed"] = False
        try:
            sig = _sign(self.ctx.keys.priv, s["my_nonce"].encode())
            await self._send_relay(s["pub"], {"t": "challenge", "sig": sig, "nonce": s["my_nonce"]})
        except Exception:
            pass
        try:
            await asyncio.wait_for(s["auth_ev"].wait(), 15)
        except asyncio.TimeoutError:
            s["state"] = "failed"
            s["link_up"].clear()
            await self._wiz_send(s["pub"], "auth timeout к %s." % short_pub(s["pub"]))
            return
        s["state"] = "up"
        s["last_rx"] = time.time()
        s["ka_task"] = asyncio.create_task(self._ka_loop(snorm))
        await self._wiz_send(s["pub"], "LINK UP + auth: %s" % self.ctx.peers.label(s["pub"]))

    async def send_envelope(self, pub, envelope):
        snorm = norm_pub(pub)
        s = self.sessions.get(snorm)
        if s is None or not s["link_up"].is_set():
            if self.router is not None:
                try:
                    await self._send_relay(pub, {"t": "relay-msg", "env": envelope})
                    return
                except Exception:
                    return
            return
        addr = s.get("addr") or s.get("peer_ext")
        if not addr or not addr[0]:
            return
        out = {"from": self.ctx.keys.pub, "env": envelope}
        try:
            loop = asyncio.get_event_loop()
            await loop.sock_sendto(
                self.sock, ENV + json.dumps(out, ensure_ascii=False).encode(), addr)
        except Exception:
            pass


@wizard.startup
async def _net_startup(ctx):
    ctx.links = Links(ctx)
    try:
        await ctx.links.start()
        await wizard.wizard.send(
            "link up: udp %d ext=%s router=%s" % (
                ctx.links.lport, ctx.links.my_ext,
                "on" if ctx.links.router else "off (no signaling)"), "")
    except Exception as e:
        await wizard.wizard.send("link start failed: %r" % (e,), "")


@wizard.shutdown
async def _net_shutdown(ctx):
    links = getattr(ctx, "links", None)
    if links is not None:
        try:
            await links.stop()
        except Exception:
            pass


@wizard.command(command="connect", desc="подключиться: /connect <pub|name>", role="admin")
async def cmd_connect(ctx, message, target: str = ""):
    links = getattr(ctx, "links", None)
    if links is None or links.sock is None:
        return "link down (нет сокета)."
    if not target:
        return "usage: /connect <pub|name>"
    pub = ctx.peers.resolve(target) or clean_pub(target)
    if not pub or len(pub) < 32:
        return "похоже не pub."
    snorm = norm_pub(pub)
    s = links.sessions.get(snorm)
    if s is not None and s["link_up"].is_set():
        return "уже connected: %s" % ctx.peers.label(pub)
    if s is not None and s.get("state") in ("wait-accept", "wizard", "punching", "auth"):
        return "заявка уже идет (/link_cancel — отмена)."
    known = ctx.peers.known(pub)
    s = links._sess(snorm, pub)
    s["state"] = "wait-accept"
    s["accepted_ev"] = asyncio.Event()
    s["denied"] = False
    s["ready_ev"] = asyncio.Event()
    if not links.my_ext:
        ext, _n = await links.measure_ext()
        if ext:
            links.my_ext = ext
    if links.my_ext is None:
        links._drop(snorm)
        return "STUN молчит, ext неизвестен."
    try:
        await links._send_relay(pub, {"t": "invite",
            "ext": [links.my_ext[0], links.my_ext[1]], "known": known})
    except Exception as e:
        links._drop(snorm)
        return "invite не ушел: %r" % (e,)

    async def _resend():
        while not s.get("accepted_ev").is_set():
            await asyncio.sleep(INVITE_RESEND)
            if s.get("accepted_ev").is_set():
                break
            try:
                await links._send_relay(pub, {"t": "invite",
                    "ext": [links.my_ext[0], links.my_ext[1]], "known": known})
            except Exception:
                break
    s["invite_task"] = asyncio.create_task(_resend())

    async def _waiter():
        try:
            await asyncio.wait_for(s["accepted_ev"].wait(), ACCEPT_TIMEOUT)
        except asyncio.TimeoutError:
            await links._wiz_send(pub, "accept timeout от %s." % short_pub(pub))
            links._drop(snorm)
            return
        t = s.get("invite_task")
        if t is not None and not t.done():
            t.cancel()
        if s.get("denied"):
            links._drop(snorm)
            return
        if not known:
            await pair_request(ctx, pub, "net", from_pub="")
            return
        s["state"] = "ready"
        try:
            await links._send_relay(pub, {"t": "ready"})
        except Exception:
            pass
        try:
            await asyncio.wait_for(s["ready_ev"].wait(), 30)
        except asyncio.TimeoutError:
            await links._wiz_send(pub, "ready timeout от %s." % short_pub(pub))
            links._drop(snorm)
            return
        await links._punch_and_auth(snorm)
    asyncio.create_task(_waiter())
    ctx.last = pub
    return "запрос отправлен %s. /link_cancel — отмена." % short_pub(pub)


@wizard.command(command="links", desc="сессии")
async def cmd_links(ctx):
    links = getattr(ctx, "links", None)
    if links is None:
        return "link down."
    if not links.sessions:
        return "нет сессий."
    out = []
    for _np, s in links.sessions.items():
        out.append("%s | %s | %s | %s" % (
            ctx.peers.label(s["pub"]), s.get("state", "?"),
            ("%s:%s" % s["addr"]) if s.get("addr") else "-",
            "up" if s["link_up"].is_set() else "down"))
    return "\n".join(out)


@wizard.command(command="disconnect", desc="/disconnect <pub|name>")
async def cmd_disconnect(ctx, target: str = ""):
    links = getattr(ctx, "links", None)
    if links is None:
        return "link down."
    if not target:
        return "usage: /disconnect <pub|name>"
    pub = ctx.peers.resolve(target) or clean_pub(target)
    s = links.sessions.get(norm_pub(pub))
    if s is None:
        return "нет сессии."
    try:
        await links._send_relay(pub, {"t": "bye"})
    except Exception:
        pass
    links._drop(norm_pub(pub))
    return "отключен: %s (пир сохранен)" % ctx.peers.label(pub)


@wizard.command(command="link_cancel", desc="отмена исходящей заявки")
async def cmd_link_cancel(ctx):
    links = getattr(ctx, "links", None)
    if links is None:
        return "link down."
    n = 0
    for snorm, s in list(links.sessions.items()):
        if s.get("state") in ("wait-accept", "wizard"):
            try:
                await links._send_relay(s["pub"], {"t": "abort", "reason": "cancel"})
            except Exception:
                pass
            links._drop(snorm)
            n += 1
    return "отменено заявок: %d" % n if n else "нет исходящих заявок."


@wizard.command(command="forget", desc="/forget <pub|name>")
async def cmd_forget(ctx, target: str = ""):
    if not target:
        return "usage: /forget <pub|name>"
    pub = ctx.peers.resolve(target) or clean_pub(target)
    d = getattr(ctx.peers, "_d", {})
    if pub in d:
        del d[pub]
        ctx.peers.save()
        links = getattr(ctx, "links", None)
        if links is not None:
            links._drop(norm_pub(pub))
        return "забыт: %s" % short_pub(pub)
    return "не найден."
