# Модульная подсистема авторизации для Flask

Переносимая подсистема авторизации (Anonimous, Windows) для веб-приложений на Flask. Для легкого добавления в существующий проект.

### Возможности

-   **Модульность**: Вся логика инкапсулирована в папке `auth_subsystem`.
-   **Конфигурация**: Тип авторизации выбирается в файле `config.ini`.
-   **Поддерживаемые типы**:
    -   `windows`: Интегрированная аутентификация Windows (Kerberos/NTLM).
    -   `anonymous`: Открытый доступ (для отладки или публичных сайтов).
-   **Простота использования**: Защита страниц осуществляется с помощью простого декоратора `@login_required`.
-   **Стилизация**: Использует Bootstrap и Font Awesome, которые подключаются локально.

---

### 1. Структура файлов

```
/ваш_проект
├── auth_subsystem/
│   ├── static/
│   │   └── vendor/
│   │       ├── bootstrap/
│   │       │   ├── css/bootstrap.min.css
│   │       │   └── js/bootstrap.bundle.min.js
│   │       └── fontawesome/
│   │           ├── css/all.min.css
│   │           └── webfonts/ (папка со файлами шрифтов)
│   ├── templates/
│   │   └── login.html
│   ├── __init__.py         # Основная логика
│   └── config.ini          # Файл настроек
│
├── example_app/            # Пример использования
│   ├── templates/
│   │   ├── index.html
│   │   └── protected.html
│   ├── app.py
│   └── requirements.txt
│
└── README.md
```

---

### 2. Установка и настройка

#### 2.1. Скачивание статических файлов

Перед запуском вам необходимо скачать и разместить статические файлы.

1.  **Bootstrap**:
    -   Скачайте с [getbootstrap.com](https://getbootstrap.com).
    -   Поместите `bootstrap.min.css` в `auth_subsystem/static/vendor/bootstrap/css/`.
    -   Поместите `bootstrap.bundle.min.js` в `auth_subsystem/static/vendor/bootstrap/js/`.

2.  **Font Awesome**:
    -   Скачайте Free-версию с [fontawesome.com](https://fontawesome.com/download).
    -   Скопируйте `css/all.min.css` из архива в `auth_subsystem/static/vendor/fontawesome/css/`.
    -   Скопируйте **всю папку `webfonts`** из архива в `auth_subsystem/static/vendor/fontawesome/`.

#### 2.2. Установка зависимостей Python

Для работы примера нужны `Flask` и `pywin32` (для Windows-аутентификации).

```shell
cd example_app
pip install -r requirements.txt
```

---

### 3. Как подключить к вашему проекту

1.  **Скопируйте** папку `auth_subsystem` в корень вашего проекта.

2.  В основном файле вашего Flask-приложения (`app.py`):
    -   Установите **секретный ключ** для сессий.
    -   Импортируйте `auth_bp` и `login_required`.
    -   Зарегистрируйте Blueprint.

    ```python
    from flask import Flask
    from auth_subsystem import auth_bp, login_required

    app = Flask(__name__)

    # Обязательно для работы сессий!
    app.config['SECRET_KEY'] = 'your-super-secret-key'

    # Регистрация подсистемы
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # ... ваши маршруты
    ```

3.  **Защитите** нужные страницы с помощью декоратора `@login_required`.

    ```python
    @app.route('/admin_panel')
    @login_required
    def admin_panel():
        return "Это секретная админ-панель."
    ```

---

### 4. Безопасность: Секретный ключ (SECRET_KEY)

Крайне важно правильно обращаться с секретным ключом `app.config['SECRET_KEY']`.

**Что он делает?**
Секретный ключ используется для **криптографической подписи** данных сессии. Он гарантирует, что данные сессии (хранящиеся в cookie в браузере) не были изменены злоумышленником. По умолчанию Flask **не шифрует** содержимое сессии, а только защищает его от подделки.

**Как правильно хранить ключ?**
Никогда не храните секретный ключ в открытом виде в исходном коде, особенно если проект находится в системе контроля версий (Git). Лучшая практика — загружать его из переменных окружения.

**Пример реализации:**

*Замените в `app.py`:*
```python
# ПЛОХО: ключ в открытом виде
app.config['SECRET_KEY'] = 'your-super-secret-key'
```

*На это:*
```python
import os

# ХОРОШО: ключ загружается из окружения
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'default-key-for-dev-only')
app.config['SECRET_KEY'] = SECRET_KEY
```

**Как задать переменную окружения:**

*   **Windows (Command Prompt):**
    ```cmd
    set FLASK_SECRET_KEY="your-very-long-and-random-secret-key"
    python app.py
    ```
*   **Windows (PowerShell):**
    ```powershell
    $env:FLASK_SECRET_KEY="your-very-long-and-random-secret-key"
    python app.py
    ```
*   **Linux/macOS:**
    ```bash
    export FLASK_SECRET_KEY="your-very-long-and-random-secret-key"
    python app.py
    ```

**Как сгенерировать надежный ключ:**
Вы можете использовать встроенные средства Python для создания случайного ключа. Выполните в терминале:
```shell
python -c "import os; print(os.urandom(24).hex())"
```

---

### 5. Конфигурация

Отредактируйте файл `auth_subsystem/config.ini`, чтобы изменить поведение авторизации.

```ini
[auth]
# Допустимые значения:
# windows   - для интегрированной аутентификации
# anonymous - для открытого доступа
type = windows
```

---

### 6. Запуск демонстрационного приложения

1.  Убедитесь, что вы выполнили шаги 2.1 и 2.2.
2.  Перейдите в папку `example_app`.
3.  Запустите приложение:
    ```shell
    python app.py
    ```
4.  Откройте в браузере `http://localhost:5000`.
    -   Попробуйте перейти на "Защищенную страницу".
    -   Измените `type` в `config.ini` на `anonymous` и перезапустите сервер, чтобы увидеть разницу.

**Примечание по Windows Authentication**: Для корректной работы в режиме `windows` браузер должен быть настроен для автоматической передачи учетных данных (обычно это работает "из коробки" для Edge/Chrome на доменных машинах при обращении к сайту в интранет-зоне).

Подробная информация по настройке и устранению проблем с Windows-аутентификацией доступна в файле [WINDOWS_AUTH_SETUP.md](WINDOWS_AUTH_SETUP.md).

