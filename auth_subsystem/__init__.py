import configparser
import os
import logging
import base64
from typing import Optional, Tuple, Any
import logging.handlers
from functools import wraps
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    g,
    Response
)

try:
    import sspi
    import sspicon
    import win32security
    SSPI_AVAILABLE = True
except ImportError:
    SSPI_AVAILABLE = False
    logging.warning("pywin32 not available, Windows authentication will not work")

# --- Logging Configuration ---
def setup_auth_logger():
    """Настройка логгера для подсистемы аутентификации."""
    logger = logging.getLogger('auth_subsystem')
    
    if logger.handlers:
        return logger
    
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, 'auth.log')
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, 
        maxBytes=1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    try:
        parser = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(__file__), 'config.ini')
        parser.read(config_path)
        
        console_logging = parser.getboolean('logging', 'console_logging', fallback=False)
        
        if console_logging:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
            logger.info("Console logging enabled")
    except Exception as e:
        logger.warning(f"Failed to read console logging configuration: {e}")
    
    return logger

auth_logger = setup_auth_logger()

# --- Blueprint Configuration ---
auth_bp = Blueprint(
    'auth_bp',
    __name__,
    template_folder='templates',
    static_folder='static'
)

# Хранилище для SSPI контекстов (в продакшене используйте Redis или подобное)
sspi_contexts = {}

# --- Configuration Loading ---
def get_auth_config():
    """Reads and returns authorization configuration from config.ini."""
    if 'auth_config' not in g:
        parser = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(__file__), 'config.ini')
        parser.read(config_path)
        
        g.auth_config = {
            'type': parser.get('auth', 'type', fallback='anonymous'),
            'spn': parser.get('windows_auth', 'spn', fallback=None),
            'default_domain': parser.get('windows_auth', 'default_domain', fallback=None),
            'debug_logging': parser.getboolean('windows_auth', 'debug_logging', fallback=False),
            'allow_ntlm': parser.getboolean('windows_auth', 'allow_ntlm', fallback=True),
            'auth_timeout': parser.getint('windows_auth', 'auth_timeout', fallback=30)
        }
        
        g.auth_type = g.auth_config['type']
    
    return g.auth_config


def extract_username_from_token(sspi_server):
    """
    Извлекает имя пользователя из SSPI ServerAuth объекта после успешной аутентификации.
    """
    try:
        if not hasattr(sspi_server, 'ctxt') or sspi_server.ctxt is None:
            auth_logger.error("SSPI context not available")
            return None
        
        # Используем SECPKG_ATTR_NAMES - самый простой и надежный метод
        try:
            username = sspi_server.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_NAMES)
            if username and username.strip():
                auth_logger.info(f"Successfully extracted username: {username}")
                return username.strip()
            else:
                auth_logger.warning("SECPKG_ATTR_NAMES returned empty username")
        except Exception as e:
            auth_logger.error(f"Failed to extract username via SECPKG_ATTR_NAMES: {str(e)}")
        
        # Fallback: через импресонацию (на случай, если первый метод не сработал)
        try:
            import win32api
            import win32con
            
            sspi_server.ctxt.ImpersonateSecurityContext()
            
            try:
                username = win32api.GetUserNameEx(win32con.NameSamCompatible)
                if username and username.strip():
                    auth_logger.info(f"Successfully extracted username via impersonation: {username}")
                    return username.strip()
            finally:
                sspi_server.ctxt.RevertSecurityContext()
                
        except Exception as e:
            auth_logger.warning(f"Fallback impersonation method failed: {str(e)}")
        
        return None
        
    except Exception as e:
        auth_logger.error(f"Error extracting username: {str(e)}")
        import traceback
        auth_logger.debug(f"Full traceback:\n{traceback.format_exc()}")
        return None

#def windows_authenticate(auth_header, config, session_id):

def windows_authenticate(
    auth_header: str, 
    config: dict, 
    session_id: str
) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:    
    """
    Выполняет Windows аутентификацию используя SSPI (серверная сторона).
    
    Args:
        auth_header: Значение заголовка Authorization из запроса
        config: Словарь с конфигурацией Windows аутентификации
        session_id: ID сессии для сохранения состояния SSPI контекста
        
    Returns:
        Tuple (success: bool, username: str or None, challenge_token: str or None, error: str or None)
    """
    if not SSPI_AVAILABLE:
        auth_logger.error("pywin32 not available for Windows authentication")
        return False, None, None, "pywin32 not available"
    
    try:
        # Парсим заголовок
        parts = auth_header.split(' ', 1)
        if len(parts) != 2:
            return False, None, None, "Invalid authorization header format"
            
        auth_type, token = parts
        auth_logger.info(f"Processing authentication, type: {auth_type}, session: {session_id}")
        
        # Поддерживаем NTLM и Negotiate
        auth_type_upper = auth_type.upper()
        if auth_type_upper not in ['NTLM', 'NEGOTIATE']:
            auth_logger.error(f"Unsupported authentication type: {auth_type}")
            return False, None, None, f"Unsupported authentication type: {auth_type}"
        
        # Декодируем токен
        try:
            token_bytes = base64.b64decode(token)
            auth_logger.debug(f"Token decoded, length: {len(token_bytes)} bytes")
        except Exception as e:
            auth_logger.error(f"Failed to decode token: {str(e)}")
            return False, None, None, "Invalid token encoding"
        
        # Определяем пакет аутентификации
        pkg_name = auth_type_upper if auth_type_upper == "NTLM" else "Negotiate"
        
        # Проверяем, есть ли уже контекст для этой сессии
        if session_id in sspi_contexts:
            auth_logger.debug(f"Found existing SSPI context for session {session_id}")
            sspi_server = sspi_contexts[session_id]
        else:
            auth_logger.debug(f"Creating new SSPI server context with package: {pkg_name}")
            
            try:
                sspi_server = sspi.ServerAuth(pkg_name, spn=config.get('spn'))
                sspi_contexts[session_id] = sspi_server
                auth_logger.debug("SSPI ServerAuth created successfully")
            except Exception as e:
                auth_logger.error(f"Failed to create ServerAuth: {str(e)}")
                return False, None, None, f"Failed to initialize authentication: {str(e)}"
        
        # Выполняем аутентификацию
        try:
            error_code, sec_buffer = sspi_server.authorize(token_bytes)
            
            if config.get('debug_logging', False):
                auth_logger.debug(f"SSPI authorize result: error_code={error_code}")
                auth_logger.debug(f"Security buffer type: {type(sec_buffer)}")
            
        except Exception as e:
            auth_logger.error(f"SSPI authorize exception: {str(e)}")
            if session_id in sspi_contexts:
                del sspi_contexts[session_id]
            return False, None, None, f"Authentication failed: {str(e)}"
        
        # Обрабатываем результат
        if error_code == 0:
            # Аутентификация успешна!
            auth_logger.info("Authentication completed successfully")
            
            # Извлекаем имя пользователя
            username = extract_username_from_token(sspi_server)
            
            if not username or not username.strip():
                auth_logger.error("Failed to extract username from context")
                if session_id in sspi_contexts:
                    del sspi_contexts[session_id]
                return False, None, None, "Failed to extract username"
            
            # Добавляем домен по умолчанию если нужно
            default_domain = config.get('default_domain')
            if default_domain and '\\' not in username and '@' not in username:
                username = f"{default_domain}\\{username}"
            
            # Очищаем контекст после успешной аутентификации
            if session_id in sspi_contexts:
                del sspi_contexts[session_id]
            
            auth_logger.info(f"User authenticated: {username}")
            return True, username, None, None
            
        elif error_code in (sspicon.SEC_I_CONTINUE_NEEDED, 
                           sspicon.SEC_I_COMPLETE_NEEDED,
                           sspicon.SEC_I_COMPLETE_AND_CONTINUE):
            # Требуется продолжение - отправляем challenge клиенту
            auth_logger.debug("Authentication requires continuation, sending challenge")
            
            # Правильная обработка PySecBufferDesc
            challenge_token = None
            
            if sec_buffer is not None:
                try:
                    # PySecBufferDesc поддерживает доступ по индексу
                    # Получаем первый буфер
                    first_buffer = sec_buffer[0]  # type: ignore
                    
                    if hasattr(first_buffer, 'Buffer'):
                        buffer_data = first_buffer.Buffer
                        
                        if config.get('debug_logging', False):
                            auth_logger.debug(f"Buffer data type: {type(buffer_data)}")
                            if buffer_data:
                                auth_logger.debug(f"Buffer data length: {len(buffer_data)}")  # type: ignore
                        
                        if buffer_data:
                            # Конвертируем в bytes
                            if isinstance(buffer_data, bytes):
                                challenge_bytes = buffer_data
                            elif isinstance(buffer_data, str):
                                # Если это строка, кодируем в bytes
                                challenge_bytes = buffer_data.encode('latin-1')
                            else:
                                # Для других типов пробуем привести к bytes
                                try:
                                    challenge_bytes = bytes(buffer_data)  # type: ignore
                                except TypeError:
                                    # Если не получается, пробуем через memoryview
                                    challenge_bytes = bytes(memoryview(buffer_data))  # type: ignore
                            
                            challenge_token = base64.b64encode(challenge_bytes).decode('ascii')
                            auth_logger.debug(f"Challenge token generated, length: {len(challenge_token)}")
                        else:
                            auth_logger.error("Buffer data is None or empty")
                    else:
                        auth_logger.error("Buffer object has no 'Buffer' attribute")
                    
                    # Дополнительная отладка если включена
                    if config.get('debug_logging', False) and not challenge_token:
                        auth_logger.debug(f"PySecBufferDesc attributes: {[attr for attr in dir(sec_buffer) if not attr.startswith('_')]}")  # type: ignore
                        auth_logger.debug(f"First buffer attributes: {[attr for attr in dir(first_buffer) if not attr.startswith('_')]}")
                        
                except Exception as e:
                    auth_logger.error(f"Failed to process security buffer: {str(e)}")
                    if config.get('debug_logging', False):
                        import traceback
                        auth_logger.debug(f"Buffer processing traceback: {traceback.format_exc()}")
            
            if challenge_token:
                return False, None, challenge_token, None
            else:
                # Если не удалось получить challenge token
                auth_logger.error("Failed to extract challenge token from security buffer")
                if session_id in sspi_contexts:
                    del sspi_contexts[session_id]
                return False, None, None, "Authentication handshake error"
            
        else:
            # Ошибка аутентификации
            auth_logger.warning(f"SSPI authorization failed with error code: {error_code}")
            if session_id in sspi_contexts:
                del sspi_contexts[session_id]
            return False, None, None, f"Authentication failed with error code: {error_code}"
        
    except Exception as e:
        auth_logger.error(f"Windows authentication error: {str(e)}")
        if config.get('debug_logging', False):
            import traceback
            auth_logger.debug(f"Exception traceback: {traceback.format_exc()}")
        
        if session_id in sspi_contexts:
            del sspi_contexts[session_id]
            
        return False, None, None, f"Windows authentication error: {str(e)}"


# --- The Main Authentication Decorator ---
def login_required(f):
    """
    Декоратор для защиты endpoints.
    Проверяет аутентификацию пользователя в зависимости от типа,
    указанного в config.ini.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        config = get_auth_config()
        auth_type = config['type']

        auth_logger.info(f"Access attempt to {request.endpoint} from {request.remote_addr}")

        # Если пользователь уже в сессии, пропускаем
        if 'user' in session:
            return f(*args, **kwargs)

        # --- Anonymous Authentication ---
        if auth_type == 'anonymous':
            session['user'] = 'anonymous_user'
            auth_logger.info(f"Anonymous access granted to {request.remote_addr}")
            return f(*args, **kwargs)

        # --- Windows Integrated Authentication ---
        if auth_type == 'windows':
            if not SSPI_AVAILABLE:
                auth_logger.error("Windows authentication requested but pywin32 not available")
                return Response(
                    status=500,
                    response="Windows authentication is not available on this server."
                )
            
            # Получаем session ID для отслеживания состояния SSPI
            session_id = session.get('_sspi_session_id')
            if not session_id:
                import uuid
                session_id = str(uuid.uuid4())
                session['_sspi_session_id'] = session_id
                auth_logger.debug(f"Created new SSPI session: {session_id}")
            
            auth_header = request.headers.get('Authorization')

            if not auth_header:
                # Отправляем 401 с NTLM challenge
                auth_logger.info("No auth header, requesting NTLM authentication")
                
                # Определяем, какой метод предпочитаем
                www_auth_method = 'NTLM' if config.get('allow_ntlm', True) else 'Negotiate'
                
                return Response(
                    status=401,
                    headers={'WWW-Authenticate': www_auth_method},
                    response="Authentication required."
                )

            # Обрабатываем заголовок авторизации
            try:
                auth_type_header = auth_header.split(' ', 1)[0] if ' ' in auth_header else auth_header
                auth_logger.info(f"Received auth header type: {auth_type_header}")
                
                if config.get('debug_logging', False):
                    auth_logger.debug(f"Remote address: {request.remote_addr}")
                    auth_logger.debug(f"User agent: {request.headers.get('User-Agent', 'Unknown')}")
                
                # Выполняем аутентификацию
                success, username, challenge_token, error = windows_authenticate(
                    auth_header, config, session_id
                )
                
                if success:
                    # Успешная аутентификация
                    session['user'] = username
                    session.pop('_sspi_session_id', None)  # Очищаем SSPI session ID
                    auth_logger.info(f"User {username} successfully authenticated from {request.remote_addr}")
                    return f(*args, **kwargs)
                    
                elif challenge_token:
                    # Требуется продолжение handshake - отправляем challenge
                    auth_logger.debug("Sending challenge token to client")
                    www_auth_value = f"{auth_type_header} {challenge_token}"
                    return Response(
                        status=401,
                        headers={'WWW-Authenticate': www_auth_value},
                        response="Authentication in progress."
                    )
                else:
                    # Ошибка аутентификации
                    auth_logger.warning(f"Authentication failed for {request.remote_addr}: {error}")
                    session.clear()
                    
                    www_auth_method = 'NTLM' if config.get('allow_ntlm', True) else 'Negotiate'
                    return Response(
                        status=401,
                        headers={'WWW-Authenticate': www_auth_method},
                        response="Authentication failed. Please try again."
                    )
                    
            except Exception as e:
                auth_logger.error(f"Windows authentication error: {str(e)}")
                session.clear()
                
                www_auth_method = 'NTLM' if config.get('allow_ntlm', True) else 'Negotiate'
                return Response(
                    status=401,
                    headers={'WWW-Authenticate': www_auth_method},
                    response="Authentication error. Please try again."
                )

        # Если ничего не сработало, перенаправляем на страницу информации
        return redirect(url_for('auth_bp.login_info'))

    return decorated_function


# --- Blueprint Routes ---
@auth_bp.route('/login')
def login_info():
    """
    Страница информации об отказе в доступе.
    """
    return render_template('login.html'), 403

@auth_bp.route('/logout')
def logout():
    """Очищает сессию и выполняет выход."""
    session.clear()
    # Очищаем SSPI контексты для этой сессии
    session_id = session.get('_sspi_session_id')
    if session_id and session_id in sspi_contexts:
        del sspi_contexts[session_id]
    return redirect(url_for('index'))


# Периодическая очистка старых SSPI контекстов (добавьте в отдельный фоновый процесс)
def cleanup_old_sspi_contexts():
    """Очищает устаревшие SSPI контексты (вызывать периодически)."""
    # В продакшене используйте TTL в Redis или подобное решение
    pass