# Настройка Windows-аутентификации

## Требования

- Windows Server или клиентская ОС Windows
- Установленный Python 3.7+
- Библиотека pywin32
- Корректно настроенная доменная среда (для Kerberos)

## Установка

1. Установите зависимости:
```bash
pip install pywin32
```

2. Настройте config.ini:
```ini
[auth]
type = windows

[windows_auth]
# SPN для Kerberos (опционально)
spn = HTTP/server.domain.com

# Домен по умолчанию (опционально)
default_domain = CORP

# Включить отладочное логирование
debug_logging = false
```

## Возможные проблемы

### Ошибка "pywin32 not available"
**Решение:** Установите библиотеку pywin32:
```bash
pip install pywin32
```

### Ошибка аутентификации Kerberos
**Решение:** Проверьте:
1. Корректность SPN в Active Directory
2. Настройки времени на сервере и клиенте
3. Доступность контроллера домена

### NTLM аутентификация не работает
**Решение:** Убедитесь, что в config.ini включена опция:
```ini
allow_ntlm = true
```

## Логирование

Для включения детального логирования измените config.ini:
```ini
[windows_auth]
debug_logging = true

[logging]
level = DEBUG
```

Логи будут сохраняться в файле `auth_subsystem/logs/auth.log`.