\# ProjectScanner



Утилита для сканирования проектов с передачей лога нейросети.



\## Что внутри



\- `scanner.py` — GUI-сканер, генерирует текстовый лог папки

\- `probes.py` — проверка версий установленных приложений

\- `BigScan/app.py` — сканер больших файлов и дубликатов

\- `start.bat` — запуск



\## Требования



\- Windows 10/11

\- Python 3.11+

\- Tkinter (идёт с Python на Windows)



\## Запуск



&#x20;   start.bat



или



&#x20;   python scanner.py



\## Куда пишутся отчёты



\- Логи ProjectScanner: `logs/<hash\_корня>/\*.txt`

\- Отчёты BigScan: `logs/reportBigscan/<диск>/<YYYY-MM-DD>/`

