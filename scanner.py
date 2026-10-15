import os, sys, time, socket, getpass, platform, hashlib, threading, traceback, sqlite3, shutil, queue, re, fnmatch, subprocess
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import probes
try:
    from BigScan import app as bigscan_app
    _BIGSCAN_OK = True
except Exception:
    bigscan_app = None
    _BIGSCAN_OK = False
BASE = os.path.dirname(os.path.abspath(__file__))
LOGDIR = os.path.join(BASE, "logs")
DB = os.path.join(BASE, "scanner.db")
os.makedirs(LOGDIR, exist_ok=True)
KEEP_SCANS = 20
MAX_FILE = 200 * 1024
HASH_CHUNK = 64 * 1024
BINARY_SNIFF = 1024
MASK_USER = False
FULL_MODE = False
OWN_MASKS = ("log*.bat", "*patch*.bat", "*patch*.ps1")
WARN_LOG_SIZE = 50 * 1024 * 1024
NAME_LIMIT = 60
BAD_CHARS = set((60, 62, 58, 34, 47, 92, 124, 63, 42))
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "build", "dist", ".idea", ".vs", "bin", "obj", ".pytest_cache", ".mypy_cache", ".tox", "target", ".next", ".nuxt", ".cache", ".gradle", ".mvn", "backups"}
TEXT_EXT = {".py", ".pyw", ".txt", ".md", ".json", ".xml", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".bat", ".cmd", ".sh", ".ps1", ".html", ".htm", ".css", ".js", ".ts", ".jsx", ".tsx", ".c", ".cpp", ".h", ".hpp", ".cs", ".java", ".go", ".rs", ".rb", ".php", ".sql", ".csv", ".env", ".toml", ".rst", ".gitignore"}

def human(n):
    n = float(n)
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if n.__lt__(1024):
            return str(round(n, 1)) + " " + u
        n /= 1024
    return str(round(n, 1)) + " PB"

def short_ver(v):
    m = re.search(r"\d+(?:\.\d+)+", v)
    return m.group(0) if m else v.split()[0]

def sanitize_name(s):
    out = "".join(c if ord(c) not in BAD_CHARS else "_" for c in s)
    out = out.strip(". ")
    if not out:
        out = "root"
    if len(out).__gt__(NAME_LIMIT):
        out = out[:NAME_LIMIT]
    return out

def make_log_filename(number, root, ts):
    name = sanitize_name(os.path.basename(os.path.abspath(root)))
    return "[" + str(number).zfill(3) + "]_[" + name + "]_" + ts + ".txt"

def all_drives():
    drives = []
    try:
        drives = list(os.listdrives())
    except AttributeError:
        for c in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            p = c + ":\\"
            if os.path.exists(p):
                drives.append(p)
    return drives

def disk_info():
    out = []
    for d in all_drives():
        try:
            t, u, f = shutil.disk_usage(d)
            pct = int(round(u * 100.0 / t)) if t else 0
            out.append((d, t, u, f, pct))
        except OSError:
            pass
    return out

def is_own_file(p):
    if FULL_MODE:
        return False
    ap = os.path.abspath(p)
    if os.path.dirname(ap) == BASE:
        _n = os.path.basename(ap).lower()
        if any(fnmatch.fnmatch(_n, m) for m in OWN_MASKS):
            return True
    if ap == DB or ap == DB + "-wal" or ap == DB + "-shm":
        return True
    if ap == LOGDIR or ap.startswith(LOGDIR + os.sep):
        return True
    return False

def skip_dir(d):
    if FULL_MODE:
        return False
    return d in SKIP_DIRS

def is_own_log(p):
    ap = os.path.abspath(p)
    return ap == LOGDIR or ap.startswith(LOGDIR + os.sep)

def is_binary(p):
    try:
        with open(p, "rb") as f:
            chunk = f.read(BINARY_SNIFF)
        return b"\x00" in chunk
    except OSError:
        return True

def file_hash(p):
    try:
        size = os.path.getsize(p)
        h = hashlib.blake2b(digest_size=16)
        with open(p, "rb") as f:
            if size.__le__(HASH_CHUNK * 2):
                h.update(f.read())
            else:
                h.update(f.read(HASH_CHUNK))
                positions = [size * i // 8 for i in range(1, 8)]
                for pos in positions:
                    f.seek(pos)
                    h.update(f.read(HASH_CHUNK))
                f.seek(-HASH_CHUNK, 2)
                h.update(f.read(HASH_CHUNK))
        return h.hexdigest()
    except OSError:
        return None

def db_connect():
    con = sqlite3.connect(DB, timeout=15)
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, number INT, started_at REAL, finished_at REAL, root TEXT, file_count INT, dir_count INT, total_size INT)")
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_root_number ON scans(root, number)")
    con.execute("CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INT, path TEXT, rel TEXT, size INT, mtime REAL, ext TEXT, hash TEXT, FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_files_scan ON files(scan_id)")
    con.execute("CREATE TABLE IF NOT EXISTS changes(id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INT, path TEXT, kind TEXT, old_size INT, new_size INT, old_mtime REAL, new_mtime REAL, FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_changes_scan ON changes(scan_id)")
    con.execute("CREATE TABLE IF NOT EXISTS apps(id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INT, name TEXT, version TEXT, path TEXT, checked_at REAL, FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_apps_scan ON apps(scan_id)")
    con.commit()
    return con

def next_number(con, root):
    r = con.execute("SELECT MAX(number) FROM scans WHERE root=?", (root,)).fetchone()
    return (r[0] or 0) + 1

def prev_scan(con, root):
    return con.execute("SELECT id, number FROM scans WHERE root=? ORDER BY id DESC LIMIT 1", (root,)).fetchone()

def root_logdir(root):
    h = hashlib.blake2b(os.path.abspath(root).encode("utf-8"), digest_size=6).hexdigest()
    d = os.path.join(LOGDIR, h)
    os.makedirs(d, exist_ok=True)
    return d

def delete_logs_for(rdir, num):
    prefixes = ["[" + str(num).zfill(3) + "]_", "log_" + str(num).zfill(3) + "_"]
    try:
        for f in os.listdir(rdir):
            for pref in prefixes:
                if f.startswith(pref):
                    try:
                        os.remove(os.path.join(rdir, f))
                    except OSError:
                        pass
                    break
    except OSError:
        pass

def rotate(con, root, keep):
    rows = con.execute("SELECT id, number FROM scans WHERE root=? ORDER BY id DESC", (root,)).fetchall()
    if len(rows).__le__(keep):
        return
    old = rows[keep:]
    rdir = root_logdir(root)
    for sid, num in old:
        con.execute("DELETE FROM files WHERE scan_id=?", (sid,))
        con.execute("DELETE FROM changes WHERE scan_id=?", (sid,))
        con.execute("DELETE FROM apps WHERE scan_id=?", (sid,))
        con.execute("DELETE FROM scans WHERE id=?", (sid,))
        delete_logs_for(rdir, num)
    con.commit()

def collect(root, progress, cancel=None):
    files = []
    dirs = 0
    total = 0
    count = 0
    hidden = []
    for cur, subdirs, names in os.walk(root):
        if cancel is not None and cancel.is_set():
            return files, dirs, total, hidden
        for d in list(subdirs):
            p = os.path.join(cur, d)
            if skip_dir(d):
                hidden.append((os.path.relpath(p, root) + "/", "SKIP_DIRS"))
            elif is_own_file(p):
                hidden.append((os.path.relpath(p, root) + "/", "ProjectScanner"))
        subdirs[:] = [d for d in subdirs if not skip_dir(d) and not is_own_file(os.path.join(cur, d))]
        if is_own_file(cur):
            subdirs[:] = []
            continue
        if cur != root:
            dirs += 1
        for n in names:
            p = os.path.join(cur, n)
            if is_own_file(p):
                hidden.append((os.path.relpath(p, root), "ProjectScanner"))
                continue
            try:
                st = os.stat(p)
            except OSError:
                continue
            try:
                rel = os.path.relpath(p, root)
            except ValueError:
                rel = p
            ext = os.path.splitext(n)[1].lower()
            files.append((p, rel, st.st_size, st.st_mtime, ext))
            total += st.st_size
            count += 1
            if count % 200 == 0:
                progress("Сканирование... файлов: " + str(count))
    return files, dirs, total, hidden

def estimate_log_size(files):
    est = 80 * 1024
    for p, rel, sz, mt, ext in files:
        name = os.path.basename(p)
        if ext not in TEXT_EXT and name not in ("README", "LICENSE", "Makefile", "Dockerfile"):
            continue
        if is_own_log(p):
            continue
        est += min(sz, MAX_FILE) + 200
    return est

def diff(con, prev_id, cur_map):
    if prev_id is None:
        return list(cur_map.keys()), [], []
    prev = {}
    for p, s, m, h in con.execute("SELECT path, size, mtime, hash FROM files WHERE scan_id=?", (prev_id,)):
        prev[p] = (s, m, h)
    added = []
    modified = []
    deleted = []
    for p, (s, m) in cur_map.items():
        if p not in prev:
            added.append(p)
        else:
            ps, pm, ph = prev[p]
            if ps != s:
                modified.append((p, ps, s, pm, m))
            elif abs(pm - m).__gt__(1e-6):
                cur_h = file_hash(p)
                if ph is None or cur_h is None or ph != cur_h:
                    modified.append((p, ps, s, pm, m))
    for p in prev:
        if p not in cur_map:
            deleted.append(p)
    return added, modified, deleted

def write_tree(f, root):
    def rec(cur, prefix):
        try:
            entries = sorted(os.listdir(cur))
        except OSError:
            return
        entries = [e for e in entries if not skip_dir(e)]
        ds = [e for e in entries if os.path.isdir(os.path.join(cur, e))]
        fs = [e for e in entries if os.path.isfile(os.path.join(cur, e))]
        for d in ds:
            full = os.path.join(cur, d)
            if is_own_file(full):
                continue
            f.write(prefix + d + "/\n")
            rec(full, prefix + "  ")
        for x in fs:
            full = os.path.join(cur, x)
            if is_own_file(full):
                continue
            try:
                sz = os.path.getsize(full)
            except OSError:
                sz = 0
            f.write(prefix + x + " (" + human(sz) + ")\n")
    f.write(os.path.basename(root) + "/\n")
    rec(root, "  ")

def write_hidden_note(f, hidden, root):
    if not hidden:
        return
    own_root = os.path.abspath(root) == BASE
    f.write("[не показано ниже]\n")
    own = [h for h, k in hidden if k == "ProjectScanner"]
    skip = [h for h, k in hidden if k == "SKIP_DIRS"]
    if own:
        f.write("  свои файлы ProjectScanner (" + str(len(own)) + "):\n")
        for h in own[:20]:
            f.write("    " + h + "\n")
        if len(own).__gt__(20):
            f.write("    ... и ещё " + str(len(own) - 20) + "\n")
    if skip:
        f.write("  по SKIP_DIRS (" + str(len(skip)) + "):\n")
        for h in skip[:20]:
            f.write("    " + h + "\n")
        if len(skip).__gt__(20):
            f.write("    ... и ещё " + str(len(skip) - 20) + "\n")
    if own_root:
        f.write("  примечание: сканируется сама папка ProjectScanner,\n")
        f.write("  поэтому свои файлы (scanner.db*, logs/, " + ", ".join(OWN_MASKS) + ") скрыты.\n")
    f.write("\n")

def write_contents(f, root, files, progress):
    f.write("\n## СОДЕРЖИМОЕ ФАЙЛОВ\n")
    f.write("=" * 70 + "\n")
    def _is_text(ext, name):
        return ext in TEXT_EXT or name in ("README", "LICENSE", "Makefile", "Dockerfile")
    total = sum(1 for p, rel, sz, mt, ext in files if _is_text(ext, os.path.basename(p)))
    i = 0
    for p, rel, sz, mt, ext in files:
        name = os.path.basename(p)
        if not _is_text(ext, name):
            continue
        i += 1
        f.write("\n===== [" + str(i) + "/" + str(total) + "] " + rel + " =====\n")
        f.write("[" + human(sz) + "] [mtime: " + time.ctime(mt) + "]\n")
        f.write("-" * 70 + "\n")
        if is_own_log(p):
            f.write("[ПРОПУЩЕНО: лог утилиты ProjectScanner]\n")
            f.write("-" * 70 + "\n")
            continue
        if sz.__gt__(MAX_FILE):
            f.write("[ПРОПУЩЕНО: файл больше " + str(MAX_FILE // 1024) + " КБ]\n")
            f.write("-" * 70 + "\n")
            continue
        if is_binary(p):
            f.write("[ПРОПУЩЕНО: бинарный файл]\n")
            f.write("-" * 70 + "\n")
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception as e:
            f.write("[ОШИБКА ЧТЕНИЯ: " + str(e) + "]\n")
            f.write("-" * 70 + "\n")
            continue
        f.write(content)
        if not content.endswith("\n"):
            f.write("\n")
        f.write("-" * 70 + "\n")
        f.flush()
        if i % 50 == 0:
            progress("Запись лога... " + str(i) + "/" + str(total))

LOG_DESCRIPTION = (
    "## О ЛОГЕ\n"
    + "-" * 70 + "\n"
    "Этот лог создан утилитой ProjectScanner для передачи нейросети.\n\n"
    "Имя файла:\n"
    "  [NNN]_[Имя_папки]_YYYY-MM-DD_HH-MM-SS.txt\n"
    "  NNN - порядковый номер скана этой папки (от 001).\n"
    "  Имя_папки - basename корневой папки (санитизировано).\n"
    "  Двоеточия в имени файла недопустимы в Windows,\n"
    "  поэтому в таймстампе используются дефисы (23-09-09 вместо 23:09:09).\n\n"
    "Что внутри:\n"
    "  1. Метаданные скана - ОС, пользователь, время, путь, режим.\n"
    "  2. Свободное место на дисках.\n"
    "  3. Версии установленных приложений - список в probes.py.\n"
    "  4. Разница с предыдущим сканом: плюс добавлено, тильда изменено, минус удалено.\n"
    "  5. Список скрытых файлов - только в обычном режиме.\n"
    "  6. Дерево папок и файлов с размерами.\n"
    "  7. Содержимое текстовых файлов - код, конфиги, документация.\n"
    "  8. Детальный список изменений - только при повторном скане.\n\n"
    "Режимы:\n"
    "  Обычный - папки из SKIP_DIRS и свои файлы утилиты пропускаются,\n"
    "    их список выводится в секции 'не показано ниже'.\n"
    "  ПОЛНЫЙ  - обходятся ВСЕ папки и файлы.\n\n"
    "Дополнительно:\n"
    "  - Перед сканом оценивается размер будущего лога;\n"
    "    если больше 50 МБ - запрашивается подтверждение.\n"
    "  - Логи хранятся в logs/ХЭШ_КОРНЯ/ (blake2b абсолютного пути).\n"
    "  - Изменения по size+mtime; при совпадении size - сверка blake2b-хэша.\n"
    "  - Хранится не более " + str(KEEP_SCANS) + " сканов на папку.\n\n"
    "Файлы утилиты:\n"
    "  scanner.py  - GUI, оркестрация, работа с БД, генерация лога\n"
    "  probes.py   - список приложений для проверки версий\n"
    "  scanner.db  - SQLite: scans, files, changes, apps\n"
    "  logs/       - подпапки по корням проектов, внутри .txt\n\n"
)

def write_log(fn, number, root, started, finished, files, dirs, total, added, modified, deleted, apps, prev_num, prev_apps, hidden, progress, full_mode):
    with open(fn, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("ProjectScanner - ЛОГ #" + str(number).zfill(3) + "\n")
        f.write("=" * 70 + "\n")
        user = "***" if MASK_USER else getpass.getuser()
        f.write("Компьютер:    " + socket.gethostname() + "\n")
        f.write("Пользователь: " + user + "\n")
        f.write("ОС:           " + platform.platform() + "\n")
        f.write("Python:       " + sys.version.split()[0] + "\n")
        f.write("Режим:        " + ("ПОЛНЫЙ ЛОГ" if full_mode else "Обычный") + "\n")
        f.write("Дата старта:  " + time.ctime(started) + "\n")
        f.write("Дата конца:   " + time.ctime(finished) + "\n")
        f.write("Длительность: " + str(round(finished - started, 1)) + " сек\n")
        f.write("Папка:        " + root + "\n")
        f.write("Файлов:       " + str(len(files)) + "\n")
        f.write("Папок:        " + str(dirs) + "\n")
        _hf = sum(1 for _h, _k in hidden if not _h.endswith("/"))
        _hd = sum(1 for _h, _k in hidden if _h.endswith("/"))
        f.write("Скрыто:       " + str(len(hidden)) + " (файлов: " + str(_hf) + ", папок: " + str(_hd) + ")\n")
        f.write("Размер:       " + human(total) + "\n")
        f.write("=" * 70 + "\n\n")
        f.write(LOG_DESCRIPTION)
        f.write("## ДИСКИ\n" + "-" * 70 + "\n")
        for d, t, u, fr, pct in disk_info():
            f.write(d + "  " + human(t) + " всего, " + human(fr) + " свободно (" + str(pct) + "% занято)\n")
        f.write("\n")
        f.write("## ВЕРСИИ ПРИЛОЖЕНИЙ\n" + "-" * 70 + "\n")
        inst = [n + " " + short_ver(v) for n, v, p in apps if v != "НЕ УСТАНОВЛЕНО"]
        miss = [n for n, v, p in apps if v == "НЕ УСТАНОВЛЕНО"]
        f.write("Установлены: " + ", ".join(inst) + "\n\n")
        f.write("Не установлены: " + ", ".join(miss) + "\n\n")
        if prev_apps:
            f.write("## ИЗМЕНЕНИЯ ВЕРСИЙ (с #" + str(prev_num).zfill(3) + ")\n" + "-" * 70 + "\n")
            any_change = False
            for name, ver, path in apps:
                old = prev_apps.get(name)
                sv = ver if ver == "НЕ УСТАНОВЛЕНО" else short_ver(ver)
                if old and old != sv:
                    f.write(name + ": " + old + "  ->  " + sv + "\n")
                    any_change = True
            if not any_change:
                f.write("Без изменений.\n")
            f.write("\n")
        if prev_num is None:
            f.write("## ИЗМЕНЕНИЯ\nПервый скан для этой папки.\n\n")
        else:
            f.write("## ИЗМЕНЕНИЯ (сравнение с #" + str(prev_num).zfill(3) + ")\n" + "-" * 70 + "\n")
            f.write("Добавлено: " + str(len(added)) + "\n")
            f.write("Изменено:  " + str(len(modified)) + "\n")
            f.write("Удалено:   " + str(len(deleted)) + "\n\n")
        f.write("## СТРУКТУРА\n" + "-" * 70 + "\n")
        if full_mode:
            f.write("[ПОЛНЫЙ РЕЖИМ] все папки и файлы показаны, включая .git, node_modules, scanner.db*\n\n")
        else:
            write_hidden_note(f, hidden, root)
        write_tree(f, root)
        write_contents(f, root, files, progress)
        if prev_num is not None and (added or modified or deleted):
            f.write("\n## ИЗМЕНЕНИЯ (детально)\n" + "-" * 70 + "\n")
            for p in added:
                f.write("+ " + p + "\n")
            for p, osz, nsz, om, nm in modified:
                f.write("~ " + p + "  (" + human(osz) + "  ->  " + human(nsz) + ")\n")
            for p in deleted:
                f.write("- " + p + "\n")

msg_q = queue.Queue()
CANCEL = threading.Event()

def worker(root_dir):
    con = None
    try:
        def progress(text):
            msg_q.put(("progress", text))
        files, dirs, total, hidden = collect(root_dir, progress, CANCEL)
        if CANCEL.is_set():
            msg_q.put(("cancel",))
            return
        est = estimate_log_size(files)
        est_mb = est / 1024.0 / 1024.0
        if est.__gt__(WARN_LOG_SIZE):
            done = threading.Event()
            ans = [False]
            def _ask():
                ans[0] = messagebox.askyesno("Большой лог", "Ожидаемый размер лога: ~" + str(round(est_mb, 2)) + " МБ\n\nЭто больше 50 МБ. Продолжить?")
                done.set()
            root.after(0, _ask)
            done.wait()
            if not ans[0]:
                msg_q.put(("cancel",))
                return
        msg_q.put(("progress", "Сканирование..."))
        con = db_connect()
        started = time.time()
        number = next_number(con, root_dir)
        prev = prev_scan(con, root_dir)
        prev_id = prev[0] if prev else None
        prev_num = prev[1] if prev else None
        prev_apps = {}
        if prev_id:
            for n, v, pa in con.execute("SELECT name, version, path FROM apps WHERE scan_id=?", (prev_id,)):
                prev_apps[n] = v if v == "НЕ УСТАНОВЛЕНО" else short_ver(v)
        cur_map = {p: (s, m) for p, _, s, m, _ in files}
        added, modified, deleted = diff(con, prev_id, cur_map)
        hash_map = {}
        for p in added:
            hash_map[p] = file_hash(p)
        for p, _, _, _, _ in modified:
            hash_map[p] = file_hash(p)
        apps = probes.collect_versions()
        finished = time.time()
        cur = con.execute("INSERT INTO scans(number, started_at, finished_at, root, file_count, dir_count, total_size) VALUES(?,?,?,?,?,?,?)", (number, started, finished, root_dir, len(files), dirs, total))
        sid = cur.lastrowid
        rows = []
        for p, rel, s, m, e in files:
            rows.append((sid, p, rel, s, m, e, hash_map.get(p)))
        con.executemany("INSERT INTO files(scan_id, path, rel, size, mtime, ext, hash) VALUES(?,?,?,?,?,?,?)", rows)
        if added:
            con.executemany("INSERT INTO changes(scan_id, path, kind, new_size, new_mtime) VALUES(?,?,?,?,?)", [(sid, p, "added", cur_map[p][0], cur_map[p][1]) for p in added])
        if modified:
            con.executemany("INSERT INTO changes(scan_id, path, kind, old_size, new_size, old_mtime, new_mtime) VALUES(?,?,?,?,?,?,?)", [(sid, p, "modified", osz, nsz, om, nm) for p, osz, nsz, om, nm in modified])
        if deleted:
            con.executemany("INSERT INTO changes(scan_id, path, kind) VALUES(?,?,?)", [(sid, p, "deleted") for p in deleted])
        con.executemany("INSERT INTO apps(scan_id, name, version, path, checked_at) VALUES(?,?,?,?,?)", [(sid, n, v if v == "НЕ УСТАНОВЛЕНО" else short_ver(v), pa, time.time()) for n, v, pa in apps])
        con.commit()
        rotate(con, root_dir, KEEP_SCANS)
        ts = time.strftime("%Y-%m-%d_%H-%M-%S")
        fn = os.path.join(root_logdir(root_dir), make_log_filename(number, root_dir, ts))
        write_log(fn, number, root_dir, started, finished, files, dirs, total, added, modified, deleted, apps, prev_num, prev_apps, hidden, progress, FULL_MODE)
        con.close()
        msg_q.put(("done", fn, len(files), len(added), len(modified), len(deleted), len(hidden), FULL_MODE))
    except Exception as e:
        if con:
            try:
                con.close()
            except Exception:
                pass
        msg_q.put(("error", str(e) + "\n\n" + traceback.format_exc()))

def scan():
    global FULL_MODE
    d = path_var.get().strip()
    if not d or not os.path.isdir(d):
        d = filedialog.askdirectory(title="Выберите папку")
        if not d:
            return
        path_var.set(d)
    FULL_MODE = bool(full_var.get())
    for i in tree.get_children():
        tree.delete(i)
    btn_scan.config(state="disabled")
    btn_choose.config(state="disabled")
    try:
        btn_cancel.config(state="normal")
    except Exception:
        pass
    pb.start(10)
    status.config(text="Подсчёт файлов...")
    root.update_idletasks()
    CANCEL.clear()
    threading.Thread(target=worker, args=(d,), daemon=True).start()

def cancel_scan():
    CANCEL.set()
    try:
        status.config(text="Отмена...")
    except Exception:
        pass

def poll():
    try:
        while True:
            msg = msg_q.get_nowait()
            if msg[0] == "progress":
                status.config(text=msg[1])
            elif msg[0] == "done":
                pb.stop()
                btn_scan.config(state="normal")
                btn_choose.config(state="normal")
                try:
                    btn_cancel.config(state="disabled")
                except Exception:
                    pass
                fill_tree("", path_var.get())
                status.config(text="Готово. Файлов: " + str(msg[2]) + " | Скрыто: " + str(msg[6]))
                mode = " [ПОЛНЫЙ]" if msg[7] else ""
                messagebox.showinfo("Готово", "Лог" + mode + ":\n" + msg[1] + "\n\nДобавлено: " + str(msg[3]) + "\nИзменено: " + str(msg[4]) + "\nУдалено: " + str(msg[5]) + "\nСкрыто: " + str(msg[6]))
            elif msg[0] == "cancel":
                pb.stop()
                btn_scan.config(state="normal")
                btn_choose.config(state="normal")
                try:
                    btn_cancel.config(state="disabled")
                except Exception:
                    pass
                status.config(text="Отменено пользователем")
            elif msg[0] == "error":
                pb.stop()
                btn_scan.config(state="normal")
                btn_choose.config(state="normal")
                try:
                    btn_cancel.config(state="disabled")
                except Exception:
                    pass
                status.config(text="Ошибка")
                messagebox.showerror("Ошибка", msg[1])
    except queue.Empty:
        pass
    root.after(100, poll)

_LAZY_DONE = set()

def _fill_children(node, path):
    try:
        entries = sorted(os.listdir(path))
    except OSError:
        return
    entries = [e for e in entries if not skip_dir(e)]
    for e in entries:
        p = os.path.join(path, e)
        if is_own_file(p):
            continue
        try:
            is_d = os.path.isdir(p)
        except OSError:
            is_d = False
        if is_d:
            cid = tree.insert(node, "end", text=e + "/", values=("", p), open=False)
            tree.insert(cid, "end", text="...", values=("", ""))
        else:
            try:
                sz = os.path.getsize(p)
            except OSError:
                sz = 0
            tree.insert(node, "end", text=e, values=(human(sz), p))

def _lazy_open(event):
    iid = tree.focus()
    if not iid or iid in _LAZY_DONE:
        return
    _LAZY_DONE.add(iid)
    for c in tree.get_children(iid):
        tree.delete(c)
    vals = tree.item(iid, "values")
    if not vals or len(vals) < 2:
        return
    p = vals[1]
    if p and os.path.isdir(p):
        _fill_children(iid, p)

def fill_tree(node, path):
    _LAZY_DONE.clear()
    for i in tree.get_children(node):
        tree.delete(i)
    _fill_children(node, path)

def open_bigscan():
    if not _BIGSCAN_OK:
        messagebox.showerror("BigScan", "Модуль BigScan не найден\n\nОжидался: BigScan\\app.py")
        return
    try:
        bigscan_app.open_bigscan(root)
    except Exception as e:
        messagebox.showerror("BigScan", "Ошибка запуска:\n" + str(e))

def open_logs():
    try:
        os.startfile(LOGDIR)
    except Exception as e:
        messagebox.showerror("Ошибка", str(e))

def show_apps():
    con = db_connect()
    row = con.execute("SELECT MAX(id) FROM scans").fetchone()
    sid = row[0] if row else None
    if not sid:
        con.close()
        messagebox.showinfo("Версии", "Сначала выполните хотя бы один скан")
        return
    rows = con.execute("SELECT name, version, path FROM apps WHERE scan_id=? ORDER BY name", (sid,)).fetchall()
    info = con.execute("SELECT number, root FROM scans WHERE id=?", (sid,)).fetchone()
    con.close()
    if not rows:
        messagebox.showinfo("Версии", "Нет данных")
        return
    header = ""
    if info:
        header = "Из скана #" + str(info[0]).zfill(3) + " (" + info[1] + ")\n" + "-" * 60 + "\n"
    lines = [header] if header else []
    for n, v, pa in rows:
        lines.append(n.ljust(18) + " " + (v if v == "НЕ УСТАНОВЛЕНО" else short_ver(v)))
    messagebox.showinfo("Версии приложений", "\n".join(lines))

def show_disks():
    lines = []
    for d, t, u, fr, pct in disk_info():
        lines.append(d + "  свободно " + human(fr) + " из " + human(t) + " (" + str(pct) + "% занято)")
    messagebox.showinfo("Диски", "\n".join(lines) if lines else "Нет данных")

root = tk.Tk()
root.title("ProjectScanner v3.8")
root.geometry("1050x680")
path_var = tk.StringVar()
full_var = tk.BooleanVar(value=False)
top = tk.Frame(root)
top.pack(fill="x", padx=5, pady=5)
btn_choose = tk.Button(top, text="...", width=3, command=lambda: path_var.set(filedialog.askdirectory() or path_var.get()))
btn_choose.pack(side="left", padx=3)
ent_path = tk.Entry(top, textvariable=path_var, width=55)
ent_path.pack(side="left", padx=3, fill="x", expand=True)
btn_scan = tk.Button(top, text="Сканировать", command=scan)
btn_scan.pack(side="left", padx=3)
btn_cancel = tk.Button(top, text="Отмена", command=cancel_scan, state="disabled")
btn_cancel.pack(side="left", padx=3)
tk.Button(top, text="Версии", command=show_apps).pack(side="left", padx=3)
tk.Button(top, text="BigScan", command=open_bigscan).pack(side="left", padx=3)
tk.Button(top, text="Открыть logs", command=open_logs).pack(side="left", padx=3)
cb_full = tk.Checkbutton(top, text="ПОЛНЫЙ ЛОГ", variable=full_var, fg="#a00")
cb_full.pack(side="left", padx=10)
fr = tk.Frame(root)
fr.pack(fill="both", expand=True, padx=5, pady=5)
tree = ttk.Treeview(fr, columns=("size", "path"))
tree.heading("#0", text="Название")
tree.heading("size", text="Размер")
tree.heading("path", text="Путь")
tree.column("#0", width=400)
tree.column("size", width=100)
tree.column("path", width=450)
vs = ttk.Scrollbar(fr, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=vs.set)
vs.pack(side="right", fill="y")
tree.pack(fill="both", expand=True)
pb = ttk.Progressbar(root, mode="indeterminate")
pb.pack(fill="x", padx=5)
status = tk.Label(root, text="Готов. Выберите папку.", anchor="w")
status.pack(fill="x", padx=5, pady=3)
tree.bind("<<TreeviewOpen>>", _lazy_open)
root.after(100, poll)
root.mainloop()
