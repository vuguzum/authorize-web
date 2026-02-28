import os
from flask import Flask, render_template, session

# --- Важный шаг ---
# Нужно добавить родительскую директорию в путь, чтобы можно было импортировать 'auth_subsystem'
# Это необходимо только для этого примера, так как auth_subsystem находится на уровень выше.
# В реальном проекте вы бы поместили auth_subsystem внутрь вашего проекта.
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# -----------------

# Импортируем blueprint и декоратор из нашей подсистемы
from auth_subsystem import auth_bp, login_required

# --- Создание и конфигурация приложения ---
app = Flask(__name__)

# Для работы сессий (session) в Flask абсолютно необходимо установить секретный ключ.
# В реальном приложении используйте более сложный ключ и храните его в безопасности.
app.config['SECRET_KEY'] = 'super-secret-key-for-session'

# Регистрируем наш blueprint. Все маршруты из auth_subsystem
# теперь доступны в приложении, например, /auth/login, /auth/logout
app.register_blueprint(auth_bp, url_prefix='/auth')


# --- Маршруты основного сайта ---

@app.route('/')
def index():
    """Главная, публичная страница."""
    return render_template('index.html')

@app.route('/protected')
@login_required  # <-- Вот так мы защищаем страницу!
def protected():
    """Защищенная страница. Доступна только после авторизации."""
    # Декоратор @login_required уже отработал и поместил 'user' в сессию.
    # Мы можем использовать эту информацию.
    return render_template('protected.html')

# --- Запуск приложения ---
if __name__ == '__main__':
    # host='0.0.0.0' делает приложение доступным в локальной сети
    # (важно для проверки Windows Authentication с других машин)
    app.run(host='0.0.0.0', port=5000, debug=True)
