# Driver-Sentry

<div align="center">

![Platform](https://img.shields.io/badge/Platform-Windows%20(x64)-0078D4?style=flat-square&logo=windows)
![Language](https://img.shields.io/badge/Language-Python%203-3776AB?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square)

**Аудитор загруженных драйверов ядра Windows и инспектор уязвимостей BYOVD.**  
*Прямой вызов Win32 `psapi!EnumDeviceDrivers` и сопоставление хэшей/имен с базой известных уязвимых подписанных драйверов (Bring Your Own Vulnerable Driver).*

</div>

---

## Архитектура

- Доступ к адресам загрузки драйверов ядра (`EnumDeviceDrivers` / `GetDeviceDriverBaseNameW`) через нативный C-интерфейс `ctypes`.
- Обнаружение драйверов с известными уязвимостями чтения/записи физической памяти ядра (например, `gdrv.sys`, `mhyprot2.sys`, `procexp.sys`).
- Не требует установки сторонних библиотек, работает на чистой стандартной библиотеке Python.

## Запуск и тесты

```powershell
python tests/test_sentry.py
python scripts/driver_sentry.py
```

## Лицензия
MIT

<!-- verified: 2026-10-30 -->