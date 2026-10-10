"""Diag: режим диагностики MERL1N. Только stdlib + опциональные либы.

/diag -> режим + помощь (интерактивный выбор NIC через FSM DiagFlow)
  /mapping_diag [-r N] [-i SEC] [-t SEC]
  /nat_check [wan_ip]
  /net_check
/nics -> перевыбор интерфейса (тот же FSM-сценарий)
/cancel -> отмена + выход из режима

Регистрация под новым API Wizard: mod = Wizard.reg_mod("diag"), интерактив
typer.ask заменён на состояния StatesGroup (DiagFlow) + wizard.mods["diag"].ask()
(одноразовый wait_reply). Вся сеть блокирующая -> asyncio.to_thread,
тяжелое -> ленивый import.

Совместимо: PyInstaller onedir (чистая Windows), Android APK.
"""
import asyncio
import ipaddress
import random
import socket
import struct
import time

from core.wizard import State, StatesGroup, Wizard
from modules import network as netinfo   # всё сетевое теперь в network.py

wizard = Wizard.reg_mod("diag")


@wizard.startup
async def _startup(ctx):
    print("[diag] ready")


@wizard.shutdown
async def _shutdown(ctx):
    print("[diag] stop")


COOKIE = 0x2112A442

# База: NAT_checker_old.STUN_SERVERS + добивка из map_probe/stun_compare.
DIAG_STUN = [
    ("stun.sipnet.ru", 3478),
    ("stun.ekiga.net", 3478),
    ("stun.sipgate.net", 3478),
    ("stun.xten.com", 3478),
    ("stun.nextcloud.com", 3478),
    ("stun.cloudflare.com", 3478),
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
]

NAT_NAMES = {
    1: "1 OPEN_INTERNET", 2: "2 UDP_FIREWALL", 3: "3 FULL_CONE",
    4: "4 RESTRICT_NAT", 5: "5 RESTRICT_PORT_NAT",
    6: "6 SYMMETRIC_NAT", 7: "7 BLOCKED",
}
DELTA_NAMES = {
    1: "1 NA", 2: "2 EQUAL", 3: "3 PRESERV",
    4: "4 INDEPENDENT", 5: "5 DEPENDENT", 6: "6 RANDOM",
}

CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")

def _is_cgnat(ip):
    try:
        return ipaddress.ip_address(ip) in CGNAT_NET
    except ValueError:
        return False


def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "?"


def _mk_req():
    tran = bytes(random.getrandbits(8) for _ in range(12))
    return (struct.pack("!HH", 0x0001, 0)
            + struct.pack("!I", COOKIE) + tran), tran


def _parse_resp(data, tran=None):
    if len(data) < 20:
        return None
    mt, ln = struct.unpack("!HH", data[:4])
    if mt != 0x0101:
        return None
    if tran is not None and data[8:20] != tran:
        return None
    pos, end = 20, 20 + ln
    while pos + 4 <= len(data) and pos < end:
        at, al = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        if pos + al > len(data):
            break
        v = data[pos:pos + al]
        if at == 0x0020 and al >= 8 and v[1] == 0x01:
            port = struct.unpack("!H", v[2:4])[0] ^ (COOKIE >> 16)
            ip = socket.inet_ntoa(
                struct.pack("!I", struct.unpack("!I", v[4:8])[0] ^ COOKIE))
            return ip, port
        if at == 0x0001 and al >= 8 and v[1] == 0x01:
            return socket.inet_ntoa(v[4:8]), struct.unpack("!H", v[2:4])[0]
        pos += (al + 3) & ~3
    return None


def _udp_once(ip, port, timeout, sock=None):
    """Одна STUN-проба. Возвращает ((ext_ip, ext_port)|None, ms)."""
    req, tran = _mk_req()
    own = False
    t0 = time.monotonic()
    try:
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("", 0))
            own = True
        sock.settimeout(timeout)
        try:
            sock.sendto(req, (ip, port))
        except Exception:
            return None, int((time.monotonic() - t0) * 1000)
        try:
            data, _ = sock.recvfrom(2048)
        except (socket.timeout, OSError):
            return None, int((time.monotonic() - t0) * 1000)
        r = _parse_resp(data, tran)
        return r, int((time.monotonic() - t0) * 1000)
    finally:
        if own:
            try:
                sock.close()
            except Exception:
                pass


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _tcp_once(host, port, timeout=4.0):
    t0 = time.monotonic()
    try:
        ip = _resolve(host)
        if not ip:
            return False, "DNS fail"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return True, "open via %s %dms" % (ip, int((time.monotonic() - t0) * 1000))
        except socket.timeout:
            return False, "timeout via %s" % ip
        except OSError as e:
            return False, "closed/refused via %s (%s)" % (ip, e)
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception as e:
        return False, "%s" % type(e).__name__



def _mqtt_handshake(host, port, timeout=8.0):
    """MQTT: TCP->CONNECT->CONNACK->SUBSCRIBE->SUBACK. Только stdlib."""
    import struct as _st

    def _es(s):
        b = s.encode("utf-8")
        return _st.pack("!H", len(b)) + b

    def _er(n):
        out = b""
        while True:
            d = n % 128
            n //= 128
            out += _st.pack("B", d | (0x80 if n else 0))
            if not n:
                return out

    def _rx(s, want, timeout):
        s.settimeout(timeout)
        try:
            hdr = s.recv(1)
        except (socket.timeout, OSError):
            return None, "timeout waiting packet"
        if not hdr:
            return None, "closed by broker"
        pt = hdr[0] >> 4
        val, pos = 0, 0
        while True:
            try:
                b = s.recv(1)
            except (socket.timeout, OSError):
                return None, "timeout reading len"
            if not b:
                return None, "closed mid-header"
            val += (b[0] & 127) * (128 ** pos)
            pos += 1
            if not (b[0] & 128) or pos > 4:
                break
        body = b""
        while len(body) < val:
            try:
                ch = s.recv(val - len(body))
            except (socket.timeout, OSError):
                return None, "timeout reading body"
            if not ch:
                return None, "closed mid-body"
            body += ch
        if pt != want:
            return None, "pkt 0x%x want 0x%x" % (pt, want)
        return body, ""

    t0 = time.monotonic()
    ip = _resolve(host)
    if not ip:
        return False, "DNS fail"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
        except socket.timeout:
            return False, "TCP timeout via %s" % ip
        except OSError as e:
            return False, "TCP closed via %s (%s)" % (ip, e)
        cid = "merlin-diag-%08x" % random.getrandbits(32)
        vh = _es("MQTT") + b"\x04\x02\x00\x1e"
        pay = _es(cid)
        s.sendall(b"\x10" + _er(len(vh) + len(pay)) + vh + pay)
        body, err = _rx(s, 0x2, timeout)
        if body is None:
            return False, "CONNACK fail: %s" % err
        if len(body) < 2 or body[1] != 0x00:
            rc = body[1] if len(body) >= 2 else -1
            return False, "CONNACK refused rc=%s" % rc
        topic = "merlin/diag/%08x" % random.getrandbits(32)
        bout = _st.pack("!H", 1) + _es(topic) + b"\x00"
        s.sendall(b"\x82" + _er(len(bout)) + bout)
        sb, err = _rx(s, 0x9, timeout)
        if sb is None:
            return False, "SUBACK fail: %s" % err
        dt = int((time.monotonic() - t0) * 1000)
        try:
            s.sendall(b"\xe0\x00")
        except Exception:
            pass
        return True, "CONNACK+SUBACK %s %dms via %s" % (topic, dt, ip)
    except OSError as e:
        return False, "io %s" % e
    finally:
        try:
            s.close()
        except Exception:
            pass



def _diag_on(ctx):
    return bool(getattr(ctx, "diag", False))


def _need_diag(ctx):
    if not _diag_on(ctx):
        return "сначала /diag — вход в режим диагностики."
    return None


def _track(ctx, name, task):
    tasks = getattr(ctx, "diag_tasks", None)
    if tasks is None:
        ctx.diag_tasks = tasks = {}
    tasks[name] = task
    return tasks


def _untrack(ctx, name):
    try:
        tasks = getattr(ctx, "diag_tasks", None)
        if tasks is not None:
            tasks.pop(name, None)
    except Exception:
        pass


def _parse_flags(args, spec):
    """Флаги вида -r 24 -i 5 -t 3. Возвращает dict + ошибку|None."""
    out = dict(spec)
    err = None
    i = 0
    while i < len(args):
        a = str(args[i])
        hit = None
        for k, flags in (("rounds", ("-r", "--rounds")),
                         ("interval", ("-i", "--interval")),
                         ("timeout", ("-t", "--timeout"))):
            if a in flags:
                hit = k
                break
        if hit is None:
            err = "неизвестный флаг '%s' (жду -r/-i/-t)" % a
            break
        if i + 1 >= len(args):
            err = "флаг %s без значения" % a
            break
        try:
            v = float(args[i + 1])
        except ValueError:
            err = "плохое значение '%s' для %s" % (args[i + 1], a)
            break
        if hit == "rounds":
            v = int(v)
            if v < 1 or v > 100:
                err = "rounds 1..100"
                break
        elif hit == "interval":
            if v < 0.5 or v > 30:
                err = "interval 0.5..30с"
                break
        else:
            if v < 1.0 or v > 10:
                err = "timeout 1..10с"
                break
        out[hit] = v
        i += 2
    return out, err


def _broker_list(ctx):
    """Брокеры: из живого Router, иначе fallback."""
    try:
        net = getattr(ctx, "net", None)
        router = getattr(net, "router", None) if net else None
        if router is not None:
            seen = []
            for c in (getattr(router, "protected_clients", None) or set()):
                h = getattr(c, "host", None)
                p = getattr(c, "port", None) or 1883
                if h:
                    seen.append((str(h), int(p)))
            if seen:
                return seen
    except Exception:
        pass
    try:
        m = netinfo.get_mqtt_server_list()   # свой stdlib-резолв вместо sidewire
        out = []
        for _af, hosts in (m or {}).items():
            if isinstance(hosts, dict):
                for h, rec in list(hosts.items())[:2]:
                    try:
                        out.append((str(h), int((rec or {}).get("port", 1883))))
                    except Exception:
                        pass
        if out:
            return out[:4]
    except Exception:
        pass
    return list(netinfo.DEFAULT_BROKERS)


_VIRTUAL_HINTS = ("virtual", "vpn", "loopback", "vethernet", "hyper-v",
                  "vmware", "tap-", "tun-", "docker", "wsl", "bluetooth",
                  "isatap", "teredo", "pseudo", "6to4")


def _nic_sort_key(name):
    low = (name or "").lower()
    return 1 if any(h in low for h in _VIRTUAL_HINTS) else 0


async def _probe_one(name, timeout=8):
    """Мягкий проб одного NIC: bind к его IPv4 + STUN-запрос. Возврат dict|None."""
    r = await asyncio.to_thread(netinfo.stun_probe_iface, name, DIAG_STUN[:2],
                                min(timeout, 5.0))
    alive, ext, addr = r
    if not alive:
        return None
    return {"name": name, "addr": addr, "ext": ext}


def _nic_name(nic):
    return nic.get("name", "?") if isinstance(nic, dict) else getattr(nic, "name", "?")


def _diag_nic(ctx):
    """Выбранный в /diag временный NIC (dict из netinfo), либо None. ctx.net НЕ трогаем."""
    return getattr(ctx, "diag_nic", None)


async def _close_diag_nic(ctx):
    ctx.diag_nic = None   # stdlib-проб не держит сокетов — просто сброс


async def _pick_nics_probed(timeout=8):
    """Список (name, nic|None, note) после мягкого STUN-проба каждого интерфейса."""
    names = await asyncio.to_thread(_iface_names)
    out = []
    for n in sorted(names, key=_nic_sort_key):
        nic = await _probe_one(n, timeout=timeout)
        out.append((n, nic, "живой" if nic is not None else "пуст/не поднялся"))
    return out


def _iface_names():
    try:
        names = [n for n, _a, _note in netinfo.list_interfaces()]
        if names:
            return names
    except Exception:
        pass
    try:
        return [n for _i, n in socket.if_nameindex()]
    except Exception:
        return []


# ------------------------------------------------------------------ FSM diag
class DiagFlow(StatesGroup):
    """Сценарий выбора NIC: проверка интерфейсов -> выбор номера."""
    ask_check = State()
    ask_pick = State()


DIAG_HELP = "команды: /mapping_diag /nat_check /net_check /nics /cancel"


@wizard.command(command="diag", desc="режим диагностики")
async def _diag(ctx, message):
    ctx.diag = True
    if getattr(ctx, "diag_tasks", None) is None:
        ctx.diag_tasks = {}
    fsm = Wizard.instance().fsm
    await fsm.set_state(message, DiagFlow.ask_check)
    return ("diag on: проверить интерфейсы и выбрать рабочий?\n"
            "  [y = проверить] [n = остаться без NIC] [list = только показать]\n"
            "nic? [y/n/list] (default y): ")


@wizard.text(DiagFlow.ask_check, idle=300)
async def _st_check(ctx, message, fsm_ctx):
    ans = message.text.strip().lower() or "y"
    if ans in ("n", "no"):
        await _close_diag_nic(ctx)
        await fsm_ctx.finish()
        return "diag on (без NIC: nat/turn-этапы будут skip).\n" + DIAG_HELP
    try:
        probed = await _pick_nics_probed()
    except Exception as e:
        await fsm_ctx.finish()
        return "diag on. проб NIC провален: %r.\n%s" % (e, DIAG_HELP)
    if not probed:
        await fsm_ctx.finish()
        return "diag on. NIC не найдены (без NIC: skip)."
    if ans == "list":
        await fsm_ctx.finish()
        lines = ["diag on. интерфейсы (только показ, NIC не выбран):"]
        for i, (n, nic, _note) in enumerate(probed, 1):
            lines.append("  [%d] %s — %s" % (i, n, "отвечает" if nic else "не отвечает"))
        lines.append(DIAG_HELP)
        return "\n".join(lines)
    lines = ["интерфейсы:"]
    for i, (n, nic, _note) in enumerate(probed, 1):
        lines.append("  [%d] %s — %s" % (i, n, "отвечает" if nic else "не отвечает"))
    alive = [(i, n, nic) for i, (n, nic, _n) in enumerate(probed, 1) if nic is not None]
    if not alive:
        await fsm_ctx.finish()
        return "\n".join(lines) + "\nживых NIC нет (без NIC: skip). " + DIAG_HELP
    fsm_ctx.get_data()["probed"] = probed
    await fsm_ctx.set(DiagFlow.ask_pick)
    return "\n".join(lines) + "\nиспользовать N? [номер / Enter = первый живой]: "


@wizard.text(DiagFlow.ask_pick, idle=300)
async def _st_pick(ctx, message, fsm_ctx):
    sel = message.text.strip()
    probed = fsm_ctx.get_data().get("probed")
    if probed is None:                  # пришли напрямую (/nics) — проб заново
        try:
            probed = await _pick_nics_probed()
        except Exception as e:
            await fsm_ctx.finish()
            return "проб NIC провален: %r.\n%s" % (e, DIAG_HELP)
    alive = [(i, n, nic) for i, (n, nic, _n) in enumerate(probed, 1) if nic is not None]
    want = alive[0][0] if sel == "" else None
    if sel != "":
        try:
            want = int(sel)
        except ValueError:
            want = None
    chosen = None
    for i, (n, nic, _n) in enumerate(probed, 1):
        if i == want and nic is not None:
            chosen = nic
    await _close_diag_nic(ctx)
    await fsm_ctx.finish()
    if chosen is None:
        return "diag on. номер неверный, NIC не выбран (skip). /nics — перевыбрать."
    ctx.diag_nic = chosen
    return ("diag on. NIC: %s (%s -> ext %s:%d).\n%s"
            % (chosen["name"], chosen.get("addr") or "?",
               chosen["ext"][0], chosen["ext"][1], DIAG_HELP))


@wizard.command(command="nics", desc="показать/выбрать интерфейс")
async def _nics(ctx, message):
    gate = _need_diag(ctx)
    if gate:
        return gate
    tasks = getattr(ctx, "diag_tasks", None) or {}
    for _nm, t in list(tasks.items()):
        if t is not None and not t.done():
            return "идет проверка, сначала /cancel."
    fsm = Wizard.instance().fsm
    try:
        probed = await _pick_nics_probed()
    except Exception as e:
        return "проб NIC провален: %r" % (e,)
    if not probed:
        return "NIC не найдены."
    await fsm.set_state(message, DiagFlow.ask_pick)
    key = await fsm.resolve_key(message)
    fsm.data_of(key)["probed"] = probed
    lines = ["интерфейсы:"]
    for i, (n, nic, _note) in enumerate(probed, 1):
        lines.append("  [%d] %s — %s" % (i, n, "отвечает" if nic else "не отвечает"))
    alive = [(i, n, nic) for i, (n, nic, _n) in enumerate(probed, 1) if nic is not None]
    if not alive:
        return "\n".join(lines) + "\nживых NIC нет."
    return "\n".join(lines) + "\nиспользовать N? [номер / Enter = первый живой]: "


@wizard.text(priority=20)
async def _diag_text(ctx, message):
    # В режиме /diag обычный текст — неверная команда, не чат.
    # state-хендлеры DiagFlow (priority 10) перехватывают ввод раньше.
    if getattr(ctx, "diag", False):
        return ("неверная команда (в /diag только /mapping_diag "
                "/nat_check /net_check /cancel)")


@wizard.command(command="cancel", desc="отмена диагностики/выход")
async def _cancel(ctx, message):
    tasks = getattr(ctx, "diag_tasks", None) or {}
    n = 0
    for _name, t in list(tasks.items()):
        try:
            if t is not None and not t.done():
                t.cancel()
                n += 1
        except Exception:
            pass
    tasks.clear()
    await _close_diag_nic(ctx)
    ctx.diag = False
    fsm = Wizard.instance().fsm
    key = await fsm.resolve_key(message)
    await fsm.storage.set(key, None)
    fsm.data_of(key).clear()
    fsm.cancel_idle(key)
    if n:
        return "cancel: остановлено задач %d, режим выкл." % n
    return "диагностика выкл."

@wizard.command(command="mapping_diag", desc="маппинг: keepalive+dst-scale")
async def _mapping(ctx, args):
    gate = _need_diag(ctx)
    if gate:
        return gate
    spec = {"rounds": 24, "interval": 5.0, "timeout": 3.0}
    opts, err = _parse_flags(list(args or []), spec)
    if err:
        return "usage: /mapping_diag [-r N] [-i SEC] [-t SEC]\n" + err
    tasks = getattr(ctx, "diag_tasks", None) or {}
    old = tasks.get("mapping")
    if old is not None and not old.done():
        return "mapping уже идет (/cancel чтобы остановить)."
    rounds, interval = int(opts["rounds"]), float(opts["interval"])
    timeout = float(opts["timeout"])
    task = asyncio.create_task(_mapping_run(ctx, rounds, interval, timeout))
    _track(ctx, "mapping", task)
    return ("mapping стартовал в фоне (r=%d i=%s t=%s). "
            "Жди вывод, /cancel — отмена." % (rounds, interval, timeout))


async def _mapping_run(ctx, rounds, interval, timeout):
    sock = None
    try:
        targets = []
        for h, p in DIAG_STUN:
            ip = await asyncio.to_thread(_resolve, h)
            if ip:
                targets.append((h, ip, p))
        if not targets:
            print("DNS fail: ни один STUN не резолвится.", flush=True)
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("", 0))
            local = sock.getsockname()[1]
        except Exception as e:
            print("UDP bind fail: %r" % (e,), flush=True)
            return
        print("discovery local=%d:" % local, flush=True)
        alive = []
        for h, ip, p in targets:
            r, ms = await asyncio.to_thread(_udp_once, ip, p, timeout, sock)
            tag = ("%s:%d" % r) if r else "TIMEOUT"
            print("  %-22s -> %s %dms" % ("%s:%d" % (h, p), tag, ms), flush=True)
            if r:
                alive.append((h, ip, p))
        if not alive:
            print("STUN молчат.", flush=True)
            return
        h0, ip0, p0 = alive[0]
        print("[A] keepalive -> %s:%s x%d:" % (h0, p0, rounds), flush=True)
        first, changes = None, 0
        for i in range(1, rounds + 1):
            r, _m = await asyncio.to_thread(_udp_once, ip0, p0, timeout, sock)
            if r and first is None:
                first = r
            if r and first and r != first:
                changes += 1
                print("  A#%02d %s:%d  <-- CHANGED" % (i, r[0], r[1]), flush=True)
            else:
                print("  A#%02d %s" % (i, ("%s:%d" % r) if r else "TIMEOUT"), flush=True)
            if i < rounds:
                await asyncio.sleep(interval)
        print("[A] итог: смен ext=%d/%d" % (changes, rounds), flush=True)
        base = first
        drift_at = None
        print("[B] dst-scale тем же сокетом:", flush=True)
        for i, (h, ip, p) in enumerate(alive):
            r, _m = await asyncio.to_thread(_udp_once, ip, p, timeout, sock)
            tag = ("%s:%d" % r) if r else "TIMEOUT"
            note = ""
            if r and base and r != base and drift_at is None:
                drift_at = i + 1
                note = "  <-- DRIFT"
            print("  B#%02d %-22s -> %s%s" % (i + 1, h, tag, note), flush=True)
        if drift_at is None:
            print("[B] итог: держится на %d dst" % len(alive), flush=True)
        else:
            print("[B] итог: уплыл на dst #%d" % drift_at, flush=True)
        print("base_ext=%s" % (("%s:%d" % base) if base else "?"), flush=True)
    except asyncio.CancelledError:
        print("mapping отменен (/cancel).", flush=True)
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass
        _untrack(ctx, "mapping")

@wizard.command(command="nat_check", desc="NAT: stdlib-классификатор + два сокета")
async def _nat(ctx, args):
    gate = _need_diag(ctx)
    if gate:
        return gate
    wan_ip = None
    if args:
        try:
            ipaddress.ip_address(str(args[0]))
            wan_ip = str(args[0])
        except ValueError:
            return "плохой wan_ip '%s'" % args[0]
    tasks = getattr(ctx, "diag_tasks", None) or {}
    old = tasks.get("nat")
    if old is not None and not old.done():
        return "nat_check уже идет (/cancel чтобы остановить)."
    task = asyncio.create_task(_nat_run(ctx, wan_ip))
    _track(ctx, "nat", task)
    return "nat_check стартовал в фоне. Жди вывод, /cancel — отмена."


async def _nat_run(ctx, wan_ip):
    s1 = s2 = None
    try:
        # 1) классификатор NAT из netinfo (замена aionetiface load_nat)
        nat_note = "skip: нет STUN-серверов"
        try:
            nic = _diag_nic(ctx)
            bind_addr = nic["addr"] if nic and nic.get("addr") else None
            server = DIAG_STUN[0]
            alt = DIAG_STUN[1] if len(DIAG_STUN) > 1 else server
            nat = await asyncio.wait_for(
                asyncio.to_thread(netinfo.classify_nat, server, alt, 2.5,
                                  2, DIAG_STUN),
                timeout=90)
            t = nat.get("type")
            d = nat.get("delta") or {}
            dt = d.get("type")
            nat_note = "%s delta=%s open=%s predict=%s hard=%s ext=%s%s%s" % (
                NAT_NAMES.get(t, t),
                DELTA_NAMES.get(dt, dt),
                nat.get("is_open"), nat.get("can_predict"),
                nat.get("is_hard"), nat.get("ext", "?"),
                (" via " + bind_addr) if bind_addr else "",
                (" [%s]" % nat.get("note")) if nat.get("note") else "")
        except asyncio.TimeoutError:
            nat_note = "classify_nat timeout 60с"
        except asyncio.CancelledError:
            raise
        except Exception as e:
            nat_note = "classify_nat fail: %r" % (e,)
        print("nat(stdlib): %s" % nat_note, flush=True)
        local = await asyncio.to_thread(netinfo.default_local_ip)
        print("local=%s iface=%s" % (
            local, await asyncio.to_thread(netinfo.default_route_iface)), flush=True)
        try:
            s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s1.bind(("", 0))
            s1_local = s1.getsockname()
            s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s2.bind(("", 0))
            s2_local = s2.getsockname()
            print("sockets: s1=%s:%d s2=%s:%d" % (
                s1_local[0], s1_local[1], s2_local[0], s2_local[1]), flush=True)
        except Exception as e:
            print("two-socket: bind fail %r" % (e,), flush=True)
            s1 = s2 = None
        responses = {}
        if s1 is not None:
            used = {"s1": set(), "s2": set()}
            for h, p in DIAG_STUN:
                if len(used["s1"]) >= 2 and len(used["s2"]) >= 2:
                    break
                ip = await asyncio.to_thread(_resolve, h)
                if not ip:
                    continue
                if h not in used["s1"]:
                    r, _m = await asyncio.to_thread(_udp_once, ip, p, 2.5, s1)
                    if r:
                        responses[("s1", h)] = r
                        used["s1"].add(h)
                        lp = s1.getsockname()
                        print("  s1 [%s:%d] -> %-22s -> %s:%d" % (
                            lp[0], lp[1], h, r[0], r[1]), flush=True)
                if h not in used["s2"]:
                    r, _m = await asyncio.to_thread(_udp_once, ip, p, 2.5, s2)
                    if r:
                        responses[("s2", h)] = r
                        used["s2"].add(h)
                        lp = s2.getsockname()
                        print("  s2 [%s:%d] -> %-22s -> %s:%d" % (
                            lp[0], lp[1], h, r[0], r[1]), flush=True)
        stun_ip = None
        for _k, (ip, _pt) in responses.items():
            stun_ip = ip
            break
        if stun_ip:
            print("ext=%s cgnat=%s" % (
                stun_ip, "да (100.64/10)" if _is_cgnat(stun_ip) else "нет"), flush=True)
            if wan_ip:
                if wan_ip != stun_ip:
                    print("wan %s != stun %s -> провайдерский NAT" % (wan_ip, stun_ip), flush=True)
                else:
                    print("wan == stun -> свой публичный IP", flush=True)
    except asyncio.CancelledError:
        print("nat_check отменен (/cancel).", flush=True)
    finally:
        for s in (s1, s2):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass
        _untrack(ctx, "nat")

@wizard.command(command="net_check", desc="STUN+TURN+брокеры full handshake")
async def _net(ctx):
    gate = _need_diag(ctx)
    if gate:
        return gate
    tasks = getattr(ctx, "diag_tasks", None) or {}
    old = tasks.get("net")
    if old is not None and not old.done():
        return "net_check уже идет (/cancel чтобы остановить)."
    task = asyncio.create_task(_net_run(ctx))
    _track(ctx, "net", task)
    return "net_check стартовал в фоне. Жди вывод, /cancel — отмена."


async def _net_run(ctx):
    try:
        print("[STUN] raw:", flush=True)
        ok = 0
        for h, p in DIAG_STUN:
            ip = await asyncio.to_thread(_resolve, h)
            if not ip:
                print("  STUN %-22s FAIL DNS fail" % ("%s:%d" % (h, p)), flush=True)
                continue
            r, ms = await asyncio.to_thread(_udp_once, ip, p, 3.0, None)
            if r:
                ok += 1
                print("  STUN %-22s OK %s:%d %dms" % ("%s:%d" % (h, p), r[0], r[1], ms), flush=True)
            else:
                print("  STUN %-22s FAIL timeout" % ("%s:%d" % (h, p)), flush=True)
        print("[STUN] raw итог %d/%d" % (ok, len(DIAG_STUN)), flush=True)
        # pipe-тест через выбранный NIC: bind к его адресу + два независимых запроса
        nic = _diag_nic(ctx)
        if nic is not None and nic.get("addr"):
            pok = 0
            for h, p2 in DIAG_STUN[:2]:
                ip = await asyncio.to_thread(_resolve, h)
                if not ip:
                    continue
                r, _ms = await asyncio.to_thread(
                    netinfo.stun_query, ip, p2, 4.0, None, nic["addr"])
                if r:
                    pok += 1
            print("[STUN] pipe (%s) %d/2" % (nic["name"], pok), flush=True)
        else:
            print("[STUN] pipe skip: no nic", flush=True)
        try:
            if nic is not None:
                # публичные TURN-серверы (openrelay) + резерв; при DNS-провале одного пробуем следующий
                servers = [("openrelay.metered.ca", 80),
                           ("openrelay.projectlaptop.co", 3478),
                           ("numb.voslogin.com", 3478)]
                done, note = False, ""
                for rec in servers[:3]:
                    r = await asyncio.to_thread(netinfo.turn_allocate, rec, 6.0)
                    if r["status"] == "alloc":
                        done, note = True, "alloc OK on %s -> relay %s" % (rec[0], r["relay"])
                        break
                    if r["status"] == "challenge":
                        done, note = True, "%s: reachable (%s)" % (rec[0], r["note"])
                        break
                    note = "%s: %s" % (rec[0], r["note"])
                print("[TURN] %s" % (("OK - " + note) if done else ("FAIL - " + (note or "no servers"))), flush=True)
            else:
                print("[TURN] skip: no nic", flush=True)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print("[TURN] fail: %r" % (e,), flush=True)
        brokers = _broker_list(ctx)
        print("[BROKERS] %d шт: TCP + CONNECT/CONNACK + SUB/SUBACK" % len(brokers), flush=True)
        for h, p in brokers:
            ok_tcp, note = await asyncio.to_thread(_tcp_once, h, p, 4.0)
            if not ok_tcp:
                print("  %-28s TCP FAIL %s" % ("%s:%d" % (h, p), note), flush=True)
                continue
            ok_m, note_m = await asyncio.to_thread(_mqtt_handshake, h, p, 8.0)
            if ok_m:
                print("  %-28s MQTT OK %s" % ("%s:%d" % (h, p), note_m), flush=True)
            else:
                print("  %-28s MQTT FAIL %s (TCP был ok)" % ("%s:%d" % (h, p), note_m), flush=True)
    except asyncio.CancelledError:
        print("net_check отменен (/cancel).", flush=True)
    finally:
        _untrack(ctx, "net")


