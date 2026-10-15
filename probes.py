# probes.py - список приложений для проверки версий
# Патч v2.4: Edge теперь парсится (передаётся весь вывод)
import shutil
import subprocess

APPS = [
    ("Python",          ["python", "--version"]),
    ("pip",             ["python", "-m", "pip", "--version"]),
    ("Git",             ["git", "--version"]),
    ("Node.js",         ["node", "--version"]),
    ("npm",             ["npm", "--version"]),
    ("Yarn",            ["yarn", "--version"]),
    ("pnpm",            ["pnpm", "--version"]),
    ("Java",            ["java", "-version"]),
    ("Maven",           ["mvn", "-version"]),
    ("Gradle",          ["gradle", "--version"]),
    ("Docker",          ["docker", "--version"]),
    ("Docker Compose",  ["docker", "compose", "version"]),
    ("kubectl",         ["kubectl", "version", "--client"]),
    ("CMake",           ["cmake", "--version"]),
    ("Ninja",           ["ninja", "--version"]),
    ("gcc",             ["gcc", "--version"]),
    ("clang",           ["clang", "--version"]),
    ("rustc",           ["rustc", "--version"]),
    ("Go",              ["go", "version"]),
    ("PHP",             ["php", "--version"]),
    ("Ruby",            ["ruby", "--version"]),
    ("SQLite",          ["sqlite3", "--version"]),
    ("PostgreSQL",      ["psql", "--version"]),
    ("ffmpeg",          ["ffmpeg", "-version"]),
    ("curl",            ["curl", "--version"]),
    ("7-Zip",           ["7z"]),
    ("PowerShell",      ["powershell", "-Command", "$PSVersionTable.PSVersion.ToString()"]),
    ("Microsoft Edge",  ["reg", "query", "HKEY_CURRENT_USER\\Software\\Microsoft\\Edge\\BLBeacon", "/v", "version"]),
]

def _run(cmd):
    path = shutil.which(cmd[0])
    if not path:
        return "", None
    use_shell = path.lower().endswith((".cmd", ".bat", ".ps1"))
    try:
        args = " ".join([chr(34) + path + chr(34)] + cmd[1:]) if use_shell else [path] + cmd[1:]
        r = subprocess.run(args, capture_output=True, timeout=5, text=True, errors="replace", shell=use_shell)
        return ((r.stdout or "") + (r.stderr or "")).strip(), path
    except subprocess.TimeoutExpired:
        return "TIMEOUT", path
    except Exception as e:
        return "ОШИБКА: " + str(e), path

def _first_line(txt):
    return txt.splitlines()[0].strip() if txt else "НЕ УСТАНОВЛЕНО"

def _parse_edge(txt):
    for line in txt.splitlines():
        parts = line.split()
        if len(parts).__ge__(3) and parts[0].lower() == "version":
            return parts[-1]
    return _first_line(txt)

def collect_versions():
    out = []
    for name, cmd in APPS:
        path = shutil.which(cmd[0])
        if not path:
            out.append((name, "НЕ УСТАНОВЛЕНО", None))
            continue
        raw, _ = _run(cmd)
        if name == "Microsoft Edge" and raw and raw != "TIMEOUT" and not raw.startswith("ОШИБКА"):
            version = _parse_edge(raw)
        else:
            version = _first_line(raw)
        out.append((name, version, path))
    return out
