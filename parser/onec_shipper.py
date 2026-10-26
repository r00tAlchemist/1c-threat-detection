#!/usr/bin/env python3
"""
Сборщик журнала регистрации 1С:Предприятие 8.3.
Читает 1Cv8Log (*.lgf + *.lgp) и дописывает новые записи в JSONL для агента любого SIEM.

Переменные окружения:
  ONEC_LOG_DIR  - каталог 1Cv8Log (обязательно)
  ONEC_OUT_DIR  - куда писать events.json и checkpoint.json
  ONEC_IB       - имя информационной базы (поле "ib")
  ONEC_POLL     - интервал опроса в секундах (по умолчанию 5)
  ONEC_MAX_MB   - размер events.json, после которого он переименовывается в events.json.1
                  (по умолчанию 100, 0 - не ротировать)

Запуск: onec_shipper.py [--once]
"""

import glob
import json
import logging
import os
import sys
import time

LOG_DIR  = os.environ.get("ONEC_LOG_DIR", "")
OUT_DIR  = os.environ.get("ONEC_OUT_DIR", r"C:\ProgramData\1c-eventlog")
INFOBASE = os.environ.get("ONEC_IB", "demo")
POLL     = int(os.environ.get("ONEC_POLL", "5"))
MAX_SIZE = int(os.environ.get("ONEC_MAX_MB", "100")) * 1024 * 1024

CHKPT   = os.path.join(OUT_DIR, "checkpoint.json")
OUTFILE = os.path.join(OUT_DIR, "events.json")

# Только stdout: под WinSW вывод пишет в файл и ротирует сама обёртка службы.
logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("1c-shipper")

_LEVELS = {"I": "information", "E": "error", "W": "warning", "N": "note"}


# ---- скобочный формат 1С ----
# И .lgf, и .lgp - это заголовок и за ним последовательность записей {...}.
# Скобки и кавычки - ASCII, поэтому границы записей ищутся прямо в байтах, без
# декодирования: байты многобайтовых символов UTF-8 с ними не совпадают.

def scan_records(data: bytes):
    """Отдаёт (end_offset, record_bytes) для каждой законченной записи {...} верхнего уровня."""
    depth, in_str, start = 0, False, 0
    for i, b in enumerate(data):
        if b == 0x22:                       # "  (экранирование "" переключает дважды - это корректно)
            in_str = not in_str
        elif in_str:
            continue
        elif b == 0x7B:                     # {
            if depth == 0:
                start = i
            depth += 1
        elif b == 0x7D and depth:           # }
            depth -= 1
            if depth == 0:
                yield i + 1, data[start:i + 1]


def parse_braces(text: str) -> list:
    """Разбирает '{a,"b",{c,d}}' в ['a', 'b', ['c', 'd']]. Кавычки со строк снимаются."""
    stack, cur, buf = [], None, []
    quoted = in_str = False
    i, n = 0, len(text)

    def flush():
        nonlocal quoted
        if buf or quoted:
            cur.append("".join(buf) if quoted else "".join(buf).strip())
        buf.clear()
        quoted = False

    while i < n:
        c = text[i]
        if in_str:
            if c == '"':
                if i + 1 < n and text[i + 1] == '"':
                    buf.append('"')
                    i += 1
                else:
                    in_str = False
            else:
                buf.append(c)
        elif c == '"':
            in_str = quoted = True
        elif c == "{":
            new = []
            if cur is not None:
                cur.append(new)
                stack.append(cur)
            cur = new
        elif c == "}":
            flush()
            if not stack:
                return cur
            cur = stack.pop()
        elif c == ",":
            flush()
        elif not c.isspace() or buf:
            buf.append(c)
        i += 1
    raise ValueError("незакрытая запись")


def _int(v) -> int:
    return int(v) if isinstance(v, str) and v.isdigit() else 0


# ---- справочники .lgf ----
# {1,uuid,"имя",idx} пользователь  {2,"имя",idx} компьютер  {3,"имя",idx} приложение
# {4,"имя",idx} событие            {5,uuid,"имя",idx} метаданные
# Остальные типы (серверы, порты, ...) не нужны и пропускаются.

USER, COMPUTER, APP, EVENT, META = 1, 2, 3, 4, 5
_UUID_KINDS = {USER, META}


class Dictionary:
    """Справочник .lgf. Файл только дописывается, поэтому читается лишь новый хвост."""

    def __init__(self, path: str):
        self.path = path
        self.offset = 0
        self.names: dict[int, dict[int, str]] = {}

    def refresh(self) -> None:
        try:
            size = os.path.getsize(self.path)
        except OSError as e:
            log.error(f"lgf: {e}")
            return
        if size < self.offset:
            log.warning("lgf: файл уменьшился, перечитываю целиком")
            self.offset, self.names = 0, {}
        if size == self.offset:
            return
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            data = f.read()
        added = consumed = 0
        for end, raw in scan_records(data):
            consumed = end
            try:
                rec = parse_braces(raw.decode("utf-8"))
                kind = _int(rec[0])
                name = rec[2] if kind in _UUID_KINDS else rec[1]
                self.names.setdefault(kind, {})[_int(rec[-1])] = name
                added += 1
            except (ValueError, IndexError, UnicodeDecodeError) as e:
                log.warning(f"lgf: битая запись на смещении {self.offset + end}: {e}")
        self.offset += consumed
        if added:
            log.info(f"lgf: +{added} записей")

    def get(self, kind: int, idx: int) -> str | None:
        return self.names.get(kind, {}).get(idx)

    def resolve(self, kind: int, idx: int, default: str = "") -> str:
        """Поиск с одной перечиткой при промахе: .lgp может сослаться на запись, которой ещё нет в справочнике."""
        if idx == 0:
            return default
        name = self.get(kind, idx)
        if name is None:
            self.refresh()
            name = self.get(kind, idx)
        return default if name is None else name


# ---- записи .lgp ----
# 0 дата  1 статус транзакции  2 {транзакция}  3 пользователь  4 компьютер  5 приложение
# 6 соединение  7 событие  8 важность  9 комментарий  10 метаданные  11 данные
# 12 представление данных  13 сервер  14 порт  15 доп. порт  16 сеанс  ...

def to_event(rec: list, d: Dictionary) -> dict:
    dt = rec[0]
    ev_idx = _int(rec[7])
    ev = {
        "id":    d.resolve(EVENT, ev_idx, f"unknown_{ev_idx}"),
        "level": _LEVELS.get(rec[8], rec[8]),
    }
    meta = d.resolve(META, _int(rec[10])) if len(rec) > 10 else ""
    if meta:
        ev["meta"] = meta
    if len(rec) > 12 and isinstance(rec[12], str) and rec[12]:
        ev["data"] = rec[12]
    return {
        "integration": "1c",
        "ib":          INFOBASE,
        "ts":          f"{dt[0:4]}-{dt[4:6]}-{dt[6:8]}T{dt[8:10]}:{dt[10:12]}:{dt[12:14]}",
        "ev":          ev,
        "user":        {"name": d.resolve(USER, _int(rec[3]))},
        "computer":    d.resolve(COMPUTER, _int(rec[4])),
        "app":         d.resolve(APP, _int(rec[5])),
        "session":     _int(rec[16]) if len(rec) > 16 else 0,
        "comment":     rec[9],
    }


def read_lgp(path: str, offset: int, d: Dictionary) -> tuple[int, list[dict]]:
    """Возвращает (новое смещение, события) для законченных записей после offset."""
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
    events, consumed = [], 0
    for end, raw in scan_records(data):
        consumed = end
        try:
            rec = parse_braces(raw.decode("utf-8"))
            if len(rec) < 10 or not (rec[0].isdigit() and len(rec[0]) == 14):
                raise ValueError("не запись события")
            events.append(to_event(rec, d))
        except (ValueError, IndexError, UnicodeDecodeError) as e:
            log.warning(f"{os.path.basename(path)}: пропущена запись на смещении {offset + end}: {e}")
    return offset + consumed, events


# ---- состояние ----

def _line_to_byte(path: str, lines: int) -> int:
    """Переводит checkpoint v1 (номер строки) в смещение в байтах."""
    with open(path, "rb") as f:
        for _ in range(lines):
            if not f.readline():
                break
        return f.tell()


def load_checkpoint() -> dict[str, int]:
    try:
        with open(CHKPT, encoding="utf-8") as f:
            c = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        log.error(f"checkpoint не читается, начинаю с начала журнала: {e}")
        return {}
    if c.get("version") == 2:
        return c["lgp"]
    log.info("checkpoint v1 (номера строк) -> v2 (смещения в байтах)")
    out = {}
    for name, lines in c.items():
        path = os.path.join(LOG_DIR, name)
        if os.path.exists(path):
            out[name] = _line_to_byte(path, lines)
    save_checkpoint(out)
    return out


def save_checkpoint(offsets: dict[str, int]) -> None:
    tmp = CHKPT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"version": 2, "lgp": offsets}, f)
    os.replace(tmp, CHKPT)


def write_events(events: list[dict]) -> None:
    with open(OUTFILE, "a", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n")


def rotate_output() -> None:
    try:
        if MAX_SIZE and os.path.getsize(OUTFILE) > MAX_SIZE:
            os.replace(OUTFILE, OUTFILE + ".1")
            open(OUTFILE, "a").close()
            log.info(f"ротация {OUTFILE}")
    except FileNotFoundError:
        pass
    except OSError as e:
        log.warning(f"ротация не удалась: {e}")


# ---- основной цикл ----

def poll(d: Dictionary, offsets: dict[str, int]) -> None:
    d.refresh()
    present, shipped, changed = set(), 0, False

    for path in sorted(glob.glob(os.path.join(LOG_DIR, "*.lgp"))):
        name = os.path.basename(path)
        present.add(name)
        offset = offsets.get(name, 0)
        try:
            if os.path.getsize(path) < offset:
                log.warning(f"{name}: файл короче checkpoint, перечитываю с начала")
                offset = 0
            new_offset, events = read_lgp(path, offset, d)
        except OSError as e:
            log.error(f"{name}: {e}")
            continue
        if events:
            write_events(events)
            shipped += len(events)
        if new_offset != offsets.get(name):
            offsets[name] = new_offset
            changed = True

    for name in set(offsets) - present:
        del offsets[name]
        changed = True

    if changed:
        save_checkpoint(offsets)
    if shipped:
        log.info(f"записано событий: {shipped}")
        rotate_output()


def main() -> None:
    if not os.path.isfile(os.path.join(LOG_DIR, "1Cv8.lgf")):
        sys.exit(f"ONEC_LOG_DIR={LOG_DIR!r}: не найден 1Cv8.lgf")
    os.makedirs(OUT_DIR, exist_ok=True)
    open(OUTFILE, "a").close()      # агенты SIEM могут не подхватить файл, которого нет на старте
    log.info(f"старт LOG_DIR={LOG_DIR} OUT_DIR={OUT_DIR} IB={INFOBASE}")
    d = Dictionary(os.path.join(LOG_DIR, "1Cv8.lgf"))
    offsets = load_checkpoint()
    once = "--once" in sys.argv[1:]

    while True:
        try:
            poll(d, offsets)
        except Exception:
            log.exception("ошибка цикла опроса")
        if once:
            return
        time.sleep(POLL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("остановлен")
