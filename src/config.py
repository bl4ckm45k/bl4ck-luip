import os
import sys
from enum import Enum
from typing import Optional

from environs import Env, EnvError
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import URL


class DatabaseType(str, Enum):
    """Supported database types."""
    POSTGRES = "postgresql"
    SQLITE = "sqlite"


class Settings(BaseModel):
    """
    Main application settings.
    
    Attributes
    ----------
    ssl_enabled : bool
        Whether SSL is enabled, False when container name is specified.
    ban_minutes : int
        Ban duration in minutes.
    ban_seconds : int
        Ban duration in seconds, calculated from ban_minutes.
    read_panel : bool
        Whether to read panel logs or only nodes (for app_mode='core').
    max_connections : int
        Maximum number of connections from different IPs per redis_ttl.
    in_docker : bool
        Whether the application is running inside a Docker container.
    secret_key : str
        Secret key for JWT authentication.
    login : str
        Administrator login name.
    password : str
        Administrator password.
    allowed_hosts : list
        List of allowed hosts for CORS and TrustedHostMiddleware.
    """
    ssl_enabled: bool = Field(default=False, description="Whether SSL is enabled")
    ban_minutes: int = Field(default=5, ge=1, le=1440, description="Ban duration in minutes")
    ban_seconds: int = Field(description="Ban duration in seconds", default=300)
    read_panel: bool = Field(default=False, description="Whether to read panel logs")
    max_connections: int = Field(default=3, ge=1, description="Maximum number of connections")
    in_docker: bool = Field(default=False, description="Whether running in Docker")
    secret_key: str = Field(..., min_length=32, description="Secret key for JWT")
    login: str = Field(..., min_length=3, description="Administrator login")
    password: str = Field(..., min_length=8, description="Administrator password")
    allowed_hosts: list[str] = Field(
        default=["*"],
        description="List of allowed hosts for CORS and TrustedHostMiddleware"
    )

    @classmethod
    @field_validator('allowed_hosts')
    def validate_allowed_hosts(cls, v):
        """Validates allowed hosts configuration."""
        if not v or len(v) == 0:
            return ["*"]  # Default to all hosts if empty
        return v

    @classmethod
    @field_validator('ban_seconds', mode='before')
    def set_ban_seconds(cls, v, values):
        if 'ban_minutes' in values:
            return values['ban_minutes'] * 60
        return v

    @classmethod
    def from_env(cls, env: Env) -> 'Settings':
        """
        Creates settings object from environment variables.
        
        Parameters
        ----------
        env : Env
            Environment variables object
            
        Returns
        -------
        Settings
            Settings object
            
        Raises
        ------
        ValueError
            If required parameters are missing or invalid
        """
        try:
            # Parse allowed hosts from environment variable
            allowed_hosts_str = env.str("ALLOWED_HOSTS", "*")
            allowed_hosts = [host.strip() for host in allowed_hosts_str.split(",")]

            return cls(
                ssl_enabled=env.bool("SSL_ENABLED", False),
                read_panel=env.bool("MARZBAN_READ_PANEL", False),
                max_connections=env.int("MAX_CONNECTIONS", 3),
                ban_minutes=env.int("BAN_MINUTES", 5),
                in_docker=os.path.exists("/.dockerenv"),
                secret_key=env.str("SECRET_KEY"),
                login=env.str("ADMIN_LOGIN"),
                password=env.str("ADMIN_PASSWORD"),
                allowed_hosts=allowed_hosts,
            )
        except EnvError as e:
            raise ValueError(f"Error loading settings: {str(e)}")


class RedisConfig(BaseModel):
    """
    Redis configuration.
    
    Attributes
    ----------
    redis_pass : Optional[str]
        Password for Redis authentication.
    redis_port : int
        Port on which the Redis server is listening.
    redis_host : str
        Host or container name where the Redis server is located.
    """
    redis_pass: Optional[str] = Field(None, description="Redis password")
    redis_port: int = Field(default=6379, ge=1, le=65535, description="Redis port")
    redis_host: str = Field(default="redis", description="Redis host")

    @classmethod
    def from_env(cls, env: Env) -> 'RedisConfig':
        """
        Creates Redis configuration from environment variables.
        
        Parameters
        ----------
        env : Env
            Environment variables object
            
        Returns
        -------
        RedisConfig
            Redis configuration object
        """
        try:
            return cls(
                redis_pass=env.str("REDIS_PASSWORD", None),
                redis_port=env.int("REDIS_PORT", 6379),
                redis_host=env.str("REDIS_HOST", "redis")
            )
        except EnvError as e:
            raise ValueError(f"Error loading Redis configuration: {str(e)}")


class Marzban(BaseModel):
    """
    Marzban configuration.
    
    Attributes
    ----------
    login : str
        Login for Marzban access.
    password : str
        Password for Marzban access.
    token_lifetime : int
        Token lifetime in minutes.
    host : str
        Hostname or IP address of the Marzban server.
    read_panel : bool
        Whether to read panel logs.
    """
    login: str = Field(..., min_length=3, description="Marzban login")
    password: str = Field(..., min_length=5, description="Marzban password")
    token_lifetime: int = Field(default=1440, ge=1, le=10080, description="Token lifetime in minutes")
    host: str = Field(..., description="Marzban host")
    read_panel: bool = Field(default=False, description="Read panel logs or not")

    @classmethod
    def from_env(cls, env: Env) -> 'Marzban':
        """
        Creates Marzban configuration from environment variables.
        
        Parameters
        ----------
        env : Env
            Environment variables object
            
        Returns
        -------
        Marzban
            Marzban configuration object
        """
        try:
            return cls(
                login=env.str("MARZBAN_LOGIN", "admin"),
                password=env.str("MARZBAN_PASSWORD", "admin"),
                host=env.str("MARZBAN_HOST", "127.0.0.1:8000"),
                read_panel=env.bool("MARZBAN_READ_PANEL", False),
                token_lifetime=env.int("MARZBAN_TOKEN_LIFETIME", 1440)
            )
        except EnvError as e:
            raise ValueError(f"Error loading Marzban configuration: {str(e)}")


class Database(BaseModel):
    """
    Database configuration.
    
    Attributes
    ----------
    db_url : str
        URL for connecting to the database.
    """
    db_url: str = Field(..., description="Database connection URL")

    @classmethod
    def from_env(cls, env: Env) -> 'Database':
        """
        Creates database configuration from environment variables.
        
        Parameters
        ----------
        env : Env
            Environment variables object
            
        Returns
        -------
        Database
            Database configuration object
        """
        try:
            db_url = env.str("DATABASE_URL", "sqlite+aiosqlite:///banned_ips.db")
            return cls(db_url=db_url)
        except EnvError as e:
            raise ValueError(f"Error loading database configuration: {str(e)}")

    @staticmethod
    def construct_sqlalchemy_url(env: Env, driver: str = "asyncpg") -> str:
        """
        Creates SQLAlchemy database URL.
        
        Parameters
        ----------
        env : Env
            Environment variables object
        driver : str
            Database driver
            
        Returns
        -------
        str
            Database connection URL
            
        Raises
        ------
        ValueError
            If connection parameters are invalid
        """
        try:
            uri = URL.create(
                drivername=f"postgresql+{driver}",
                username=env.str('DB_USER'),
                password=env.str('DB_PASS'),
                host=env.str('DB_HOST') if sys.platform != 'win32' else '127.0.0.1',
                port=env.int('DB_PORT', 5432),
                database=env.str('DB_NAME', "bl4ck_luip"),
            )
            return uri.render_as_string(hide_password=False)
        except EnvError:
            return "sqlite+aiosqlite:///banned_ips.db"
        except Exception as e:
            raise ValueError(f"Error creating database URL: {str(e)}")


class Config(BaseModel):
    """
    Main application configuration.
    
    Attributes
    ----------
    settings : Settings
        Main application settings.
    redis : RedisConfig
        Configuration for Redis.
    marzban : Marzban
        Configuration for Marzban.
    db_url : str
        URL for connecting to the database.
    """
    settings: Settings
    redis: RedisConfig
    marzban: Marzban
    db_url: str


def load_config() -> Config:
    """
    Loads configuration from environment variables.
    
    Returns
    -------
    Config
        Application configuration object
        
    Raises
    ------
    ValueError
        If configuration is invalid
    """
    try:
        env = Env()
        env.read_env('.env')

        return Config(
            settings=Settings.from_env(env),
            redis=RedisConfig.from_env(env),
            marzban=Marzban.from_env(env),
            db_url=Database.construct_sqlalchemy_url(env),
        )
    except Exception as e:
        raise ValueError(f"Error loading configuration: {str(e)}")
