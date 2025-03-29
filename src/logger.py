"""
A centralized logging module with structured output support.

This module provides a centralized logging configuration for the application.
"""
import logging
from typing import Optional

import betterlogging as bl


class LogManager:
    """
    Manages logging configuration for the application.
    """

    # Standard log format
    DEFAULT_LOG_FORMAT = "%(filename)s:%(lineno)d #%(levelname)-8s [%(asctime)s] - %(name)s - %(message)s"

    def __init__(self):
        """Initialize the logging manager."""
        self.root_logger = logging.getLogger()
        self.loggers = {}

        # Default settings
        self.log_level = logging.INFO
        self.log_to_console = True
        self.app_name = "bl4ck-luip"

    def configure(self,
                  log_level: Optional[int] = None,
                  log_to_console: Optional[bool] = None,
                  app_name: Optional[str] = None) -> None:
        """
        Configure logging parameters.
        
        Args:
            log_level: Logging level (default: INFO)
            log_to_console: Whether to log to console (default: True)
            app_name: Application name for log files (default: "bl4ck-luip")
        """
        # Update settings with provided values or keep default values
        self.log_level = log_level or self.log_level
        self.log_to_console = log_to_console if log_to_console is not None else self.log_to_console
        self.app_name = app_name or self.app_name

        # Configure root logger
        self._configure_root_logger()

        # Configure specific loggers with special levels
        self._configure_specific_loggers()

    def _configure_root_logger(self) -> None:
        """Configure the root logger with handlers and formatters."""
        # Reset root logger
        self.root_logger.handlers = []
        self.root_logger.setLevel(self.log_level)

        formatter = logging.Formatter(self.DEFAULT_LOG_FORMAT)

        # Use betterlogging for enhanced console logging
        bl.basic_colorized_config(level=self.log_level)
        for handler in self.root_logger.handlers:
            handler.setFormatter(formatter)

    def _configure_specific_loggers(self) -> None:
        """Configure specific loggers with special levels."""
        # Reduce output from noisy libraries
        logging.getLogger("httpcore.http11").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("websockets.client").setLevel(logging.INFO)
        logging.getLogger("paramiko.transport").setLevel(logging.WARNING)

    def get_logger(self, name: str) -> logging.Logger:
        """
        Get a named logger.
        
        Args:
            name: Logger name, usually __name__
            
        Returns:
            Logger instance
        """
        if name not in self.loggers:
            logger = logging.getLogger(name)
            self.loggers[name] = logger

        return self.loggers[name]

    def setup_from_config(self, environment: str = 'development') -> None:
        """Configure logging."""
        try:
            # Configure based on environment
            if environment == "production":
                self.configure(
                    log_level=logging.INFO,
                    log_to_console=True
                )
            else:  # development
                self.configure(
                    log_level=logging.DEBUG,
                    log_to_console=True
                )
        except (AttributeError, ImportError):
            # Fall back to default configuration
            self.configure()


# Create a global instance for use in other modules
log_manager = LogManager()


# Helper function to get a logger
def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger.
    
    Args:
        name: Logger name, usually __name__
        
    Returns:
        Configured logger instance
    """
    return log_manager.get_logger(name)
