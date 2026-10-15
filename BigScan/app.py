# -*- coding: utf-8 -*-
# BigScan v7 - быстрый сканер больших файлов и дубликатов.
# v7: отчёты в ..\logs\reportBigscan
# Оптимизации против v5:
#   - os.scandir вместо os.walk
#   - один os.stat на файл (вместо 3-х get*)
#   - executemany батчами
#   - скип-лист системных папок (опционально)
#   - отсечка junction и symlink (защита от циклов на Windows)
#   - UI прогресс с текущей папкой
import os, sys, sqlite3, time, threading, subprocess, hashlib, csv
import tkinter as tk
from tkinter import filedialog, ttk, messagebox

BASE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE)
DBDIR = os.path.join(BASE, "db")
REPORTS = os.path.join(PROJECT_ROOT, "logs", "reportBigscan")
os.makedirs(DBDIR, exist_ok=True)
os.makedirs(REPORTS, exist_ok=True)

def _drive_tag_from_db(path):
    if not path:
        return 'all'
    base = os.path.basename(path)
    if base.startswith('scan_') and base.endswith('.db'):
        return base[5:-3] or 'all'
    return 'all'

def _migrate_legacy_reports():
    try:
        names = os.listdir(REPORTS)
    except OSError:
        return
    for name in names:
        fp = os.path.join(REPORTS, name)
        if not os.path.isfile(fp):
            continue
        ts = None
        low = name.lower()
        for pref in ('report_', 'scan_', 'ext_'):
            if name.startswith(pref) and low.endswith(('.txt', '.csv')):
                body = name[len(pref):name.rfind('.')]
                if body.isdigit():
                    ts = int(body)
                break
        if ts is None:
            continue
        date = time.strftime('%Y-%m-%d', time.localtime(ts))
        dst = os.path.join(REPORTS, '_legacy', date)
        os.makedirs(dst, exist_ok=True)
        try:
            os.replace(fp, os.path.join(dst, name))
        except OSError:
            pass

_migrate_legacy_reports()

CATS = ["All", "Cache", "CrashDump", "RecycleBin", "Installer",
        "Download", "Other", "Game", "System", "Personal"]

# Системные/мусорные папки - пропускаются в "быстром режиме".
# Не трогают содержимое диска, только исключают из обхода.
SKIP_DIRS = {
    "$recycle.bin", "system volume information",
    "winsxs", "servicing", "driverstore", "wfp", "assembly",
    "installer", "temp", "tmp", "inetcache", "webcache",
    "node_modules", ".git", ".svn", ".hg",
    "__pycache__", ".venv", "venv", ".tox", ".nox",
    ".cache", ".gradle", ".m2", ".nuget", ".npm", ".yarn",
    "package cache", "windowsapps", "windows~bt", "windows.old",
}

BATCH_SIZE = 2000

def _drive_tag(path):
    if path is None:
        return "all"
    drv = os.path.splitdrive(os.path.abspath(path))[0]
    if drv:
        return drv.replace(":", "").replace("\\", "").replace("/", "").lower()
    return "root"

def _db_for(path):
    return os.path.join(DBDIR, "scan_" + _drive_tag(path) + ".db")

def _classify(p):
    pl = p.lower()
    if "temp" in pl or "cache" in pl:
        return "Cache"
    if "crashdump" in pl or pl.endswith(".dmp") or "crashpad" in pl:
        return "CrashDump"
    if "$recycle.bin" in pl:
        return "RecycleBin"
    if pl.startswith("c:\\windows") or "winsxs" in pl or "driverstore" in pl or pl.startswith("c:\\program files"):
        return "System"
    if "steamlibrary" in pl or "steamapps" in pl:
        return "Game"
    if "\\downloads\\" in pl:
        if pl.endswith((".exe", ".msi", ".msix", ".zip", ".rar", ".7z", ".iso")):
            return "Installer"
        return "Download"
    if "\\desktop\\" in pl or "\\documents\\" in pl or "\\pictures\\" in pl or "\\videos\\" in pl:
        return "Personal"
    return "Other"

def _safety(cat):
    if cat in ("Cache", "CrashDump", "RecycleBin"):
        return "green"
    if cat in ("Installer", "Download", "Other"):
        return "yellow"
    return "red"

def _is_junction(entry):
    try:
        return entry.is_junction()
    except AttributeError:
        return False
    except OSError:
        return True

def _locked(fn):
    def w(self, *args, **kw):
        with self.lock:
            return fn(self, *args, **kw)
    return w

class BigScanWindow:
    def __init__(self, parent):
        self.win = tk.Toplevel(parent)
        self.win.title("BigScan v7")
        self.win.geometry("1150x720")
        self.conn = None
        self.db_path = None
        self.lock = threading.RLock()
        self.stop_flag = threading.Event()
        self.scan_btns = []
        self.scan_thread = None
        self.del_btns = []
        self.sort_col = "size"
        self.sort_dir = "DESC"
        self.filter_txt = ""
        self.cat_filter = "All"
        self._build()
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        self._open_last_or_default_db()

    def _on_close(self):
        self.stop_flag.set()
        _t = self.scan_thread
        if _t is not None and _t.is_alive():
            _t.join(timeout=3)
        try:
            self.win.destroy()
        except Exception:
            pass

    def _safe_status(self, txt):
        if not self.win.winfo_exists():
            return
        try:
            self.status.config(text=txt)
        except Exception:
            pass

    def _read_last_db(self):
        f = os.path.join(DBDIR, ".last")
        try:
            with open(f, "r", encoding="utf-8") as fh:
                p = fh.read().strip()
            return p or None
        except Exception:
            return None

    def _write_last_db(self, p):
        f = os.path.join(DBDIR, ".last")
        try:
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(p)
        except Exception:
            pass

    def _open_last_or_default_db(self):
        last = self._read_last_db()
        if last and os.path.exists(last):
            try:
                self._switch_db_by_file(last)
                return
            except Exception:
                pass
        for c in "CDEFGH":
            d = c + ":\\"
            if os.path.exists(d):
                self._switch_db(d)
                return

    def _switch_db(self, path):
        p = _db_for(path)
        self._switch_db_by_file(p)
        self._write_last_db(p)

    @_locked
    def _switch_db_by_file(self, p):
        if self.scan_thread is not None and self.scan_thread.is_alive():
            self.status.config(text="Идёт скан, дождитесь окончания")
            return
        if p == self.db_path:
            return
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn = sqlite3.connect(p, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, path TEXT UNIQUE, size INT, atime REAL, mtime REAL, category TEXT)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_size ON files(size)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_atime ON files(atime)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_cat ON files(category)")
        self.conn.commit()
        self.db_path = p
        self._show()

    def _build(self):
        top = tk.Frame(self.win)
        top.pack(fill="x")
        b = tk.Button(top, text="Сканировать папку", command=self._scan_dialog); b.pack(side="left", padx=3, pady=3); self.scan_btns.append(b)
        b = tk.Button(top, text="C:\\", command=lambda: self._scan_drive("C:\\")); b.pack(side="left", padx=3, pady=3); self.scan_btns.append(b)
        b = tk.Button(top, text="D:\\", command=lambda: self._scan_drive("D:\\")); b.pack(side="left", padx=3, pady=3); self.scan_btns.append(b)
        b = tk.Button(top, text="Весь ПК", command=self._scan_all); b.pack(side="left", padx=3, pady=3); self.scan_btns.append(b)
        tk.Button(top, text="Стоп", command=self._stop).pack(side="left", padx=3, pady=3)
        b = tk.Button(top, text="Удалить", command=self._del); b.pack(side="left", padx=3, pady=3); self.del_btns.append(b)
        b = tk.Button(top, text="Отчёт TXT", command=self._report); b.pack(side="left", padx=3, pady=3); self.del_btns.append(b)
        b = tk.Button(top, text="Экспорт CSV", command=self._export_csv); b.pack(side="left", padx=3, pady=3); self.del_btns.append(b)
        b = tk.Button(top, text="Сводка типов", command=self._summary_ext); b.pack(side="left", padx=3, pady=3); self.del_btns.append(b)
        b = tk.Button(top, text="Очистить БД", command=self._clear); b.pack(side="left", padx=3, pady=3); self.del_btns.append(b)

        f2 = tk.Frame(self.win)
        f2.pack(fill="x")
        tk.Label(f2, text="Мин.МБ:").pack(side="left", padx=3)
        self.min_size = tk.IntVar(value=10)
        tk.Spinbox(f2, from_=1, to=10000, textvariable=self.min_size, width=6, command=self._show).pack(side="left")
        tk.Label(f2, text="Дней:").pack(side="left", padx=3)
        self.min_days = tk.IntVar(value=0)
        tk.Spinbox(f2, from_=0, to=3650, textvariable=self.min_days, width=6, command=self._show).pack(side="left")
        tk.Label(f2, text="Фильтр:").pack(side="left", padx=3)
        self.flt_var = tk.StringVar()
        ent = tk.Entry(f2, textvariable=self.flt_var, width=25)
        ent.pack(side="left")
        ent.bind("KeyRelease", self._apply_filter)
        tk.Label(f2, text="Кат:").pack(side="left", padx=3)
        self.cat_var = tk.StringVar(value="All")
        cb = ttk.Combobox(f2, textvariable=self.cat_var, values=CATS, width=12, state="readonly")
        cb.pack(side="left")
        cb.bind("ComboboxSelected", self._apply_filter)

        f2b = tk.Frame(self.win)
        f2b.pack(fill="x")
        self.skip_sys = tk.BooleanVar(value=True)
        tk.Checkbutton(f2b, text="Быстрый режим (пропуск системных папок)",
                       variable=self.skip_sys, fg="#0a0").pack(side="left", padx=5)
        tk.Label(f2b, text="(WinSxS, $Recycle.Bin, Temp, Package Cache, node_modules, .git...)",
                 fg="#777").pack(side="left")

        self.db_label = tk.Label(self.win, text="БД: -", anchor="w", fg="#555")
        self.db_label.pack(fill="x", padx=5)

        f3 = tk.Frame(self.win)
        f3.pack(fill="x")
        tk.Button(f3, text="Открыть Temp", command=lambda: self._open_folder("Temp")).pack(side="left", padx=3)
        tk.Button(f3, text="Открыть Downloads", command=lambda: self._open_folder("Downloads")).pack(side="left", padx=3)
        tk.Button(f3, text="Открыть DXCache", command=lambda: self._open_folder("Cache")).pack(side="left", padx=3)
        tk.Button(f3, text="Открыть Reports", command=lambda: self._open_folder("Reports")).pack(side="left", padx=3)

        nb = ttk.Notebook(self.win)
        nb.pack(fill="both", expand=True)
        tab1 = tk.Frame(nb)
        nb.add(tab1, text="Файлы")
        self.tv = ttk.Treeview(tab1, columns=("c", "p", "s", "a"), show="headings")
        self.tv.heading("c", text="Кат", command=lambda: self._sort_by("category"))
        self.tv.heading("p", text="Путь")
        self.tv.heading("s", text="Размер", command=lambda: self._sort_by("size"))
        self.tv.heading("a", text="Не открывался", command=lambda: self._sort_by("atime"))
        self.tv.column("c", width=90)
        self.tv.column("p", width=650)
        self.tv.column("s", width=120)
        self.tv.column("a", width=140)
        vs = ttk.Scrollbar(tab1, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.tv.pack(fill="both", expand=True)
        self.tv.tag_configure("green", background="#d4ffd4")
        self.tv.tag_configure("yellow", background="#fff4d4")
        self.tv.tag_configure("red", background="#ffd4d4")
        self.tv.bind("Button-3", self._popup)
        self.tv.bind("Double-1", lambda e: self._open_loc())

        tab2 = tk.Frame(nb)
        nb.add(tab2, text="Дубликаты")
        self.dup_tv = ttk.Treeview(tab2, columns=("g", "n", "f"), show="headings")
        self.dup_tv.heading("g", text="Группа / Файл")
        self.dup_tv.heading("n", text="Кол-во")
        self.dup_tv.heading("f", text="Освободить")
        self.dup_tv.column("g", width=800)
        self.dup_tv.column("n", width=80)
        self.dup_tv.column("f", width=180)
        dv = ttk.Scrollbar(tab2, orient="vertical", command=self.dup_tv.yview)
        self.dup_tv.configure(yscrollcommand=dv.set)
        dv.pack(side="right", fill="y")
        self.dup_tv.pack(fill="both", expand=True)
        self.dup_btn = tk.Button(tab2, text="Найти дубликаты", command=self._find_dupes)
        self.dup_btn.pack(side="bottom", fill="x")

        self.pb = ttk.Progressbar(self.win, mode="indeterminate")
        self.pb.pack(fill="x")
        self.status = tk.Label(self.win, text="Готов", anchor="w")
        self.status.pack(fill="x")

        self.menu = tk.Menu(self.win, tearoff=0)
        self.menu.add_command(label="Открыть расположение", command=self._open_loc)
        self.menu.add_command(label="Открыть файл", command=self._open_file)
        self.menu.add_command(label="Копировать путь", command=self._copy_path)
        self.menu.add_separator()
        self.menu.add_command(label="Удалить", command=self._del)

    def _scan_dialog(self):
        d = filedialog.askdirectory(title="Папка")
        if d:
            self._scan(d)

    def _scan_drive(self, drive):
        if not os.path.exists(drive):
            messagebox.showinfo("BigScan", "Недоступен: " + drive)
            return
        self._scan(drive)

    def _scan_all(self):
        drives = []
        for c in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            d = c + ":\\"
            if os.path.exists(d):
                drives.append(d)
        if not drives:
            messagebox.showinfo("BigScan", "Диски не найдены")
            return
        self._scan(None, drives)

    def _scan(self, folder, drives=None):
        if self.scan_thread is not None and self.scan_thread.is_alive():
            return
        target = None if drives else folder
        self._switch_db(target)
        self.stop_flag.clear()
        for _b in self.scan_btns + self.del_btns:
            try:
                _b.config(state="disabled")
            except Exception:
                pass
        self.pb.start(10)
        self.status.config(text="Сканирование...")
        self.scan_thread = threading.Thread(target=self._scan_worker, args=(folder, drives), daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, folder, drives):
        n = 0
        ms = self.min_size.get() * 1024 * 1024
        skip_sys = self.skip_sys.get()
        bases = drives if drives else [folder]
        with self.lock:
            if drives:
                self.conn.execute("DELETE FROM files")
            elif folder:
                _pref = os.path.abspath(folder).rstrip(os.sep) + os.sep
                self.conn.execute("DELETE FROM files WHERE path >= ? AND path < ?", (_pref, _pref + chr(0xffff)))
            self.conn.commit()
        batch = []
        last_ui = time.time()

        def flush():
            nonlocal batch
            if not batch:
                return
            with self.lock:
                self.conn.executemany(
                    "INSERT OR REPLACE INTO files(path,size,atime,mtime,category) VALUES(?,?,?,?,?)",
                    batch)
                self.conn.commit()
            batch = []

        def walk(base):
            nonlocal n, batch, last_ui
            stack = [base]
            while stack:
                if self.stop_flag.is_set():
                    return
                cur = stack.pop()
                try:
                    with os.scandir(cur) as it:
                        for entry in it:
                            if self.stop_flag.is_set():
                                return
                            try:
                                if entry.is_symlink() or _is_junction(entry):
                                    continue
                                is_dir = entry.is_dir(follow_symlinks=False)
                                if is_dir:
                                    if skip_sys and entry.name.lower() in SKIP_DIRS:
                                        continue
                                    stack.append(entry.path)
                                    continue
                                if not entry.is_file(follow_symlinks=False):
                                    continue
                                st = entry.stat(follow_symlinks=False)
                                s = st.st_size
                                if s < ms:
                                    continue
                                cat = _classify(entry.path)
                                batch.append((entry.path, s, st.st_atime, st.st_mtime, cat))
                                n += 1
                                if len(batch) >= BATCH_SIZE:
                                    flush()
                                now = time.time()
                                if now - last_ui > 0.5:
                                    last_ui = now
                                    p = entry.path
                                    nn = n
                                    self.win.after(0, lambda pp=p, cc=nn: self._safe_status(
                                        "Найдено: " + str(cc) + " | " + pp[:90]))
                            except OSError:
                                pass
                except OSError:
                    pass

        for base in bases:
            if self.stop_flag.is_set():
                break
            walk(base)

        flush()
        nn = n
        def _finish():
            if not self.win.winfo_exists():
                return
            try:
                self.pb.stop()
                self._show()
                self.status.config(text="Готово. Найдено: " + str(nn))
            except Exception:
                pass
            for _b in self.scan_btns + self.del_btns:
                try:
                    _b.config(state="normal")
                except Exception:
                    pass
            self.scan_thread = None
        self.win.after(0, _finish)

    def _stop(self):
        self.stop_flag.set()
        self.status.config(text="Остановка...")
        _t = self.scan_thread
        if _t is not None and _t.is_alive():
            _t.join(timeout=5)

    def _sort_by(self, col):
        if self.sort_col == col and self.sort_dir == "DESC":
            self.sort_dir = "ASC"
        else:
            self.sort_dir = "DESC"
        self.sort_col = col
        self._show()

    def _apply_filter(self, *a):
        self.filter_txt = self.flt_var.get()
        self.cat_filter = self.cat_var.get()
        self._show()

    @_locked
    def _show(self):
        if not self.conn:
            return
        if self.db_path:
            self.db_label.config(text="БД: " + self.db_path)
        for i in self.tv.get_children():
            self.tv.delete(i)
        q = "SELECT id,path,size,atime,category FROM files WHERE size BETWEEN ? AND 9999999999999 AND atime BETWEEN 0 AND ? - ? AND path LIKE ?"
        params = [self.min_size.get() * 1024 * 1024, time.time(),
                  self.min_days.get() * 86400, "%" + self.filter_txt + "%"]
        if self.cat_filter != "All":
            q += " AND category=?"
            params.append(self.cat_filter)
        q += " ORDER BY " + self.sort_col + " " + self.sort_dir
        total = 0
        cnt = 0
        now = time.time()
        for i, p, s, a, cat in self.conn.execute(q, params):
            tag = _safety(cat)
            self.tv.insert("", "end", iid=str(i),
                           values=(cat, p, str(round(s / 1048576, 1)) + " MB",
                                   str(int((now - a) / 86400)) + " дн."), tags=(tag,))
            total += s
            cnt += 1
        self.status.config(text="Файлов: " + str(cnt) + " | " + str(round(total / 1073741824, 2)) + " GB")

    @_locked
    def _recycle(self, path):
        import ctypes
        from ctypes import wintypes
        class _SH(ctypes.Structure):
            _fields_ = [("hwnd", wintypes.HWND),
                        ("wFunc", wintypes.UINT),
                        ("pFrom", ctypes.c_wchar_p),
                        ("pTo", ctypes.c_wchar_p),
                        ("fFlags", ctypes.c_uint16),
                        ("fAborted", wintypes.BOOL),
                        ("hNM", ctypes.c_void_p),
                        ("lpszTitle", ctypes.c_wchar_p)]
        op = _SH()
        op.wFunc = 3
        op.pFrom = path + chr(0) + chr(0)
        op.fFlags = 0x40 + 0x10 + 0x4 + 0x400
        r = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        if r != 0:
            raise OSError("recycle failed: " + str(r))

    @_locked
    def _del(self):
        sel = list(self.tv.selection())
        if not sel:
            return
        if not messagebox.askyesno("Удалить", "В корзину " + str(len(sel)) + " файл(ов)?"):
            return
        ok = 0
        missing = 0
        errors = []
        for i in sel:
            p = self.tv.item(i)["values"][1]
            if not os.path.exists(p):
                missing += 1
                self.conn.execute("DELETE FROM files WHERE id=?", (int(i),))
                self.tv.delete(i)
                continue
            try:
                self._recycle(p)
                self.conn.execute("DELETE FROM files WHERE id=?", (int(i),))
                self.tv.delete(i)
                ok += 1
            except OSError as e:
                errors.append((p, str(e)))
        self.conn.commit()
        if errors or missing:
            lines = ["Удалено: " + str(ok), "Уже нет: " + str(missing), "Ошибок: " + str(len(errors))]
            for _p, _e in errors[:10]:
                lines.append("  " + _p + ": " + _e)
            if len(errors) > 10:
                lines.append("  ... и ещё " + str(len(errors) - 10))
            messagebox.showwarning("Удаление", chr(10).join(lines))
        self._show()

    @_locked
    def _clear(self):
        if messagebox.askyesno("Очистить", "Удалить все записи из текущей БД?"):
            self.conn.execute("DELETE FROM files")
            self.conn.commit()
            self._show()

    def _sel_path(self):
        sel = self.tv.selection()
        return self.tv.item(sel[0])["values"][1] if sel else None

    def _open_loc(self):
        p = self._sel_path()
        if p:
            subprocess.Popen(["explorer", "/select,", os.path.normpath(p)])

    def _open_file(self):
        p = self._sel_path()
        if p:
            try:
                os.startfile(p)
            except OSError as e:
                messagebox.showerror("Err", str(e))

    def _copy_path(self):
        p = self._sel_path()
        if p:
            self.win.clipboard_clear()
            self.win.clipboard_append(p)
            self.status.config(text="Скопировано")

    def _open_folder(self, kind):
        paths = {
            "Temp": os.environ.get("TEMP", ""),
            "Downloads": os.path.join(os.path.expanduser("~"), "Downloads"),
            "Cache": os.path.join(os.environ.get("LOCALAPPDATA", ""), "NVIDIA", "DXCache"),
            "Reports": os.path.abspath(REPORTS),
        }
        p = paths.get(kind, "")
        if p and os.path.exists(p):
            subprocess.Popen(["explorer", os.path.normpath(p)])
        else:
            messagebox.showinfo("Инфо", "Нет: " + p)

    def _report_dir(self):
        tag = _drive_tag_from_db(self.db_path)
        date = time.strftime('%Y-%m-%d')
        d = os.path.join(REPORTS, tag, date)
        os.makedirs(d, exist_ok=True)
        return d

    @_locked
    def _report(self):
        rows = list(self.conn.execute("SELECT path,size,atime,mtime,category FROM files ORDER BY size DESC"))
        if not rows:
            messagebox.showinfo("Отчёт", "Нет данных")
            return
        total = sum(r[1] for r in rows)
        now = time.time()
        fn = os.path.join(self._report_dir(), "report_" + str(int(time.time())) + ".txt")
        by_cat = {}
        for r in rows:
            by_cat[r[4]] = by_cat.get(r[4], 0) + r[1]
        with open(fn, "w", encoding="utf-8") as f:
            f.write("=== BigScan ===\n" + time.ctime() + "\n")
            f.write("Файлов: " + str(len(rows)) + " | Объём: " + str(round(total / 1073741824, 2)) + " GB\n\n")
            f.write("По категориям:\n")
            for k, v in sorted(by_cat.items(), key=lambda x: -x[1]):
                f.write("  " + k + ": " + str(round(v / 1073741824, 2)) + " GB\n")
            f.write("\nКат | Путь | МБ | Дней | Изменён\n")
            for p, s, a, m, cat in rows:
                f.write(cat + " | " + p + " | " + str(round(s / 1048576, 1)) + " | " +
                        str(int((now - a) / 86400)) + " | " + time.ctime(m) + "\n")
        messagebox.showinfo("Отчёт", "Сохранён:\n" + os.path.abspath(fn))

    @_locked
    def _export_csv(self):
        rows = list(self.conn.execute("SELECT category,path,size,atime,mtime FROM files ORDER BY size DESC"))
        if not rows:
            messagebox.showinfo("CSV", "Нет данных")
            return
        fn = os.path.join(self._report_dir(), "scan_" + str(int(time.time())) + ".csv")
        with open(fn, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["category", "path", "size_mb", "atime", "mtime"])
            for cat, p, s, a, m in rows:
                w.writerow([cat, p, round(s / 1048576, 2), time.ctime(a), time.ctime(m)])
        messagebox.showinfo("CSV", "Сохранён:\n" + os.path.abspath(fn))

    @_locked
    def _summary_ext(self):
        rows = list(self.conn.execute("SELECT path,size FROM files"))
        by_ext = {}
        for p, s in rows:
            e = os.path.splitext(p)[1].lower() or "(none)"
            if e in by_ext:
                by_ext[e][0] += 1
                by_ext[e][1] += s
            else:
                by_ext[e] = [1, s]
        items = sorted(by_ext.items(), key=lambda x: -x[1][1])[:30]
        fn = os.path.join(self._report_dir(), "ext_" + str(int(time.time())) + ".txt")
        with open(fn, "w", encoding="utf-8") as f:
            f.write("Ext | Файлов | GB\n")
            for e, v in items:
                f.write(e + " | " + str(v[0]) + " | " + str(round(v[1] / 1073741824, 2)) + "\n")
        messagebox.showinfo("Сводка", "Сохранена:\n" + os.path.abspath(fn))

    @_locked
    def _find_dupes(self):
        for i in self.dup_tv.get_children():
            self.dup_tv.delete(i)
        rows = list(self.conn.execute("SELECT path,size FROM files WHERE size BETWEEN 1048576 AND 9999999999999"))
        if not rows:
            self.status.config(text="Нет файлов для анализа")
            return
        try:
            self.dup_btn.config(state="disabled")
        except Exception:
            pass
        self.status.config(text="Поиск дубликатов...")
        threading.Thread(target=self._find_dupes_worker, args=(rows,), daemon=True).start()

    def _find_dupes_worker(self, rows):
        by_size = {}
        for p, s in rows:
            by_size.setdefault(s, []).append(p)
        groups = []
        freed = 0
        for s, paths in by_size.items():
            if len(paths) < 2:
                continue
            by_hash = {}
            for p in paths:
                try:
                    try:
                        hh = hashlib.md5(usedforsecurity=False)
                    except TypeError:
                        hh = hashlib.md5()
                    with open(p, "rb") as f:
                        for _ in range(16):
                            chunk = f.read(1048576)
                            if not chunk:
                                break
                            hh.update(chunk)
                    h = hh.hexdigest()
                    by_hash.setdefault(h, []).append(p)
                except OSError:
                    pass
            for h, ps in by_hash.items():
                if len(ps) > 1:
                    groups.append((s, ps))
                    freed += (len(ps) - 1) * s
        def _fill():
            try:
                for s, ps in groups:
                    parent = self.dup_tv.insert("", "end",
                        values=("Группа " + str(round(s / 1048576, 1)) + " MB",
                                "x" + str(len(ps)),
                                str(round((len(ps) - 1) * s / 1073741824, 2)) + " GB"))
                    for p in ps:
                        self.dup_tv.insert(parent, "end", values=(p, "", ""))
                self.status.config(text="Групп: " + str(len(groups)) + " | Освободить: " + str(round(freed / 1073741824, 2)) + " GB")
            finally:
                try:
                    self.dup_btn.config(state="normal")
                except Exception:
                    pass
        try:
            self.win.after(0, _fill)
        except Exception:
            pass

    def _popup(self, e):
        row = self.tv.identify_row(e.y)
        if row:
            if row not in self.tv.selection():
                self.tv.selection_set(row)
            self.menu.tk_popup(e.x_root, e.y_root)

def open_bigscan(parent):
    BigScanWindow(parent)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("BigScan v7")
    root.geometry("1150x720")
    BigScanWindow(root)
    root.mainloop()