# bl4ck-luip

## Содержание / Contents
- [English version](#english-version)
- [Русская версия](#русская-версия)

---

<a name="english-version"></a>

## Description
This project is designed for managing connections and blocking IP addresses using Marzban and a database.

## Environment Configuration
Before running the project, configure the `.env` file with the required parameters.

### General Parameters
- `BAN_MINUTES` – IP ban duration (in minutes). Default: `5`
- `MAX_CONNECTIONS` – Maximum allowed connections per user. Default: `1`

### Redis Settings
- `REDIS_PASSWORD` – Redis password (if set).
- `REDIS_PORT` – Redis server port (default `6379`).
- `REDIS_HOST` – Redis server host (default `127.0.0.1`).

### Database Settings
- `DATABASE_URL` – Database connection string. Default SQLite: `sqlite:///banned_ips.db`
- For PostgreSQL:
  ```env
  DB_HOST='127.0.0.1'
  DB_PORT=5432
  DB_USER=postgres
  DB_PASS='password'
  DB_NAME=bl4ck_luip
  DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/bl4ck_luip
  ```
- For MySQL:
  ```env
  DATABASE_URL=mysql+asyncmy://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}
  ```

### Marzban Settings
- `SSL_ENABLED` – Whether to use SSL (`True`/`False`). Default: `True`.
- `MARZBAN_LOGIN` – Marzban panel login.
- `MARZBAN_PASSWORD` – Marzban panel password.
- `MARZBAN_HOST` – Domain name or IP address of the Marzban server.
- `MARZBAN_READ_PANEL` – `True` if using the Marzban panel for connections, otherwise `False`.
- `MARZBAN_TOKEN_LIFETIME` – Token lifetime (in minutes). Default: `1440`.

### Administrator Settings
- `ADMIN_LOGIN` – Administrator login.
- `ADMIN_PASSWORD` – Administrator password.

## Running the Project
1. Install dependencies (if required).
2. Create and configure the `.env` file based on the provided example.
3. Start the application.

## Features
- Monitoring IP connections to Marzban nodes
- Automatic banning of IPs exceeding connection limits
- Support for multiple database backends (SQLite, PostgreSQL, MySQL)
- Docker and docker-compose support for easy deployment
- Asynchronous processing for high performance

## Support
If you have any questions or issues, please contact [me on TG: pay4fallwall](https://pay4fallwall.t.me/ "pay4fallwall")

[Back to Contents](#содержание--contents)

---

<a name="русская-версия"></a>

## Описание
Этот проект предназначен для управления подключениями и блокировки IP-адресов с использованием Marzban и базы данных.

## Настройка окружения
Перед запуском проекта настройте файл `.env` с необходимыми параметрами.

### Основные параметры
- `BAN_MINUTES` – Длительность блокировки IP (в минутах). По умолчанию: `5`
- `MAX_CONNECTIONS` – Максимальное количество разрешенных подключений на пользователя. По умолчанию: `1`

### Настройки Redis
- `REDIS_PASSWORD` – Пароль Redis (если установлен).
- `REDIS_PORT` – Порт сервера Redis (по умолчанию `6379`).
- `REDIS_HOST` – Хост сервера Redis (по умолчанию `127.0.0.1`).

### Настройки базы данных
- `DATABASE_URL` – Строка подключения к базе данных. По умолчанию SQLite: `sqlite:///banned_ips.db`
- Для PostgreSQL:
  ```env
  DB_HOST='127.0.0.1'
  DB_PORT=5432
  DB_USER=postgres
  DB_PASS='password'
  DB_NAME=bl4ck_luip
  DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/bl4ck_luip
  ```
- Для MySQL:
  ```env
  DATABASE_URL=mysql+asyncmy://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}
  ```

### Настройки Marzban
- `SSL_ENABLED` – Использовать ли SSL (`True`/`False`). По умолчанию: `True`.
- `MARZBAN_LOGIN` – Логин для панели Marzban.
- `MARZBAN_PASSWORD` – Пароль для панели Marzban.
- `MARZBAN_HOST` – Доменное имя или IP-адрес сервера Marzban.
- `MARZBAN_READ_PANEL` – `True`, если используется панель Marzban для подключений, иначе `False`.
- `MARZBAN_TOKEN_LIFETIME` – Время жизни токена (в минутах). По умолчанию: `1440`.

### Настройки администратора
- `ADMIN_LOGIN` – Логин администратора.
- `ADMIN_PASSWORD` – Пароль администратора.

## Запуск проекта
1. Установите зависимости (при необходимости).
2. Создайте и настройте файл `.env` на основе предоставленного примера.
3. Запустите приложение.

## Функциональность
- Мониторинг IP-подключений к узлам Marzban
- Автоматическая блокировка IP-адресов, превышающих лимиты подключений
- Поддержка нескольких типов баз данных (SQLite, PostgreSQL, MySQL)
- Поддержка Docker и docker-compose для удобного развертывания
- Асинхронная обработка для высокой производительности

## Поддержка
Если у вас есть вопросы или проблемы, пожалуйста, свяжитесь со мной [в Telegram: pay4fallwall](https://pay4fallwall.t.me/ "pay4fallwall")

[Вернуться к содержанию](#содержание--contents)

