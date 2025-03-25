import json
import logging
import os
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict

from environs import Env, EnvError
from sqlalchemy import URL


@dataclass
class Settings:
    """
    Settings class.

    Attributes
    ----------
    ssl_enabled : bool
        Используется ли SSL, при указании имени контейнера - False.
    read_panel : bool
        Читать ли логи самой панели или только нод (для режима app_mode='core').
    host : str
        Имя хоста, домен или имя контейнера.
    redis_ttl : int
        Временный интервал в котором учитывается кол-во соединений с разных IP.
    max_connections : int
        Максимальное кол-во подключений с разных IP за redis_ttl.
    """
    ssl_enabled: bool
    ban_minutes: int
    ban_seconds: int
    read_panel: bool
    max_connections: int
    in_docker: bool
    secret_key: str
    login: str
    password: str

    @staticmethod
    def from_env(env: Env):
        ssl_enabled = env.bool("SSL_ENABLED", False)
        read_panel = env.bool("READ_PANEL", False)
        max_connections = env.int("MAX_CONNECTIONS", 3)
        ban_minutes = env.int("BAN_MINUTES", 5)
        ban_seconds = ban_minutes * 60
        in_docker = os.path.exists("/.dockerenv")
        secret_key = env.str("SECRET_KEY")
        login = env.str("ADMIN_LOGIN")
        password = env.str("ADMIN_PASSWORD")
        return Settings(
            ssl_enabled=ssl_enabled,
            read_panel=read_panel,
            ban_minutes=ban_minutes,
            ban_seconds=ban_seconds,
            max_connections=max_connections,
            in_docker=in_docker,
            secret_key=secret_key,
            login=login,
            password=password,
        )


@dataclass
class RedisConfig:
    """
    Redis configuration class.

    Attributes
    ----------
    redis_pass : Optional(str)
        The password used to authenticate with Redis.
    redis_port : Optional(int)
        The port where Redis server is listening.
    redis_host : Optional(str)
        The host or container name where Redis server is located.
    """

    redis_pass: Optional[str]
    redis_port: int
    redis_host: str

    @staticmethod
    def from_env(env: Env):
        """
        Creates the RedisConfig object from environment variables.
        """
        redis_pass = env.str("REDIS_PASSWORD", None)
        redis_port = env.int("REDIS_PORT", 6379)
        redis_host = env.str("REDIS_HOST", "redis")

        return RedisConfig(
            redis_pass=redis_pass,
            redis_port=redis_port,
            redis_host=redis_host
        )


@dataclass
class Marzban:
    login: str
    password: str
    token_lifetime: int
    host: str
    read_panel: bool

    @staticmethod
    def from_env(env: Env):
        login = env.str("MARZBAN_LOGIN", "admin")
        password = env.str("MARZBAN_PASSWORD", "admin")
        host = env.str("MARZBAN_HOST", "127.0.0.1:8000")
        read_panel = env.bool("MARZBAN_READ_PANEL", False)
        if os.path.exists("/.dockerenv") and read_panel:
            logging.error(f'')
            if any(x in host for x in ["127.0.0.1", "localhost", "0.0.0.0"]):
                logging.error('It is not possible to manage network connections in the docker at a local address.\n'
                              'Specify the public IP of the marzban server or the domain name for SSH connection.')
                read_panel = False
        token_lifetime = env.int("MARZBAN_TOKEN_LIFETIME", 1440)
        return Marzban(
            login, password, token_lifetime, host, read_panel,
        )


@dataclass
class NodeConfig:
    user_name: str
    port: int
    private_key_path: str
    private_key_password: str
    password: str


@dataclass
class Database:
    db_url: str

    @staticmethod
    def from_env(env: Env):
        db_url = env.str("DATABASE_URL", "sqlite+aiosqlite:///banned_ips.db")
        return Database(db_url)

    @staticmethod
    def construct_sqlalchemy_url(env, driver="asyncpg") -> str:
        """
        Constructs and returns a SQLAlchemy URL for this database configuration.
        """
        try:
            uri = URL.create(
                drivername=f"postgresql+{driver}",
                username=env.str('DB_USER', ),
                password=env.str('DB_PASS'),
                host=env.str('DB_HOST') if sys.platform != 'win32' else '127.0.0.1',
                port=env.int('DB_PORT', 5432),
                database=env.str('DB_NAME', "bl4ck_luip"),
            )
        except EnvError:
            return "sqlite+aiosqlite:///banned_ips.db"
        return uri.render_as_string(hide_password=False)


@dataclass
class Config:
    settings: Settings
    redis: RedisConfig
    marzban: Marzban
    db_url: str


def load_config():
    env = Env()
    env.read_env('.env')
    return Config(
        settings=Settings.from_env(env),
        redis=RedisConfig.from_env(env),
        marzban=Marzban.from_env(env),
        db_url=Database.construct_sqlalchemy_url(env),
    )
