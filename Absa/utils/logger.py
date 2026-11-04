"""
ABSA Color Logger
Provides color-coded async logging with colorama support.
"""

import logging
import sys
from typing import Optional

try:
    from colorama import init, Fore, Style

    init(autoreset=True)
    _COLORAMA_AVAILABLE = True
except ImportError:
    _COLORAMA_AVAILABLE = False


class ColorFormatter(logging.Formatter):
    """Custom formatter that adds ANSI color codes to log levels."""

    _COLOR_MAP = {
        logging.DEBUG: Fore.CYAN if _COLORAMA_AVAILABLE else "\033[36m",
        logging.INFO: Fore.GREEN if _COLORAMA_AVAILABLE else "\033[32m",
        logging.WARNING: Fore.YELLOW if _COLORAMA_AVAILABLE else "\033[33m",
        logging.ERROR: Fore.RED if _COLORAMA_AVAILABLE else "\033[31m",
        logging.CRITICAL: (Fore.RED + Style.BRIGHT) if _COLORAMA_AVAILABLE else "\033[1;31m",
    }
    _RESET = Style.RESET_ALL if _COLORAMA_AVAILABLE else "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with colored level name."""
        color = self._COLOR_MAP.get(record.levelno, self._RESET)
        record.levelname = f"{color}{record.levelno:<8}{self._RESET}"
        return super().format(record)


# Default format strings (used if config import fails)
_DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    Get or create a named logger with color formatting.

    Args:
        name: Logger name (typically module name like 'infrastructure', 'scanner', etc.)
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured logging.Logger instance
    """
    log_format = _DEFAULT_LOG_FORMAT
    date_format = _DEFAULT_DATE_FORMAT

    try:
        import config
        log_format = getattr(config, "LOG_FORMAT", _DEFAULT_LOG_FORMAT)
        date_format = getattr(config, "LOG_DATE_FORMAT", _DEFAULT_DATE_FORMAT)
    except ImportError:
        pass

    logger_name = f"absa.{name}" if not name.startswith("absa.") else name
    logger = logging.getLogger(logger_name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColorFormatter(fmt=log_format, datefmt=date_format))
        logger.addHandler(handler)

    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    logger.propagate = False

    return logger


def set_global_level(level: str) -> None:
    """
    Set the log level for all ABSA loggers.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    for logger_name in logging.Logger.manager.loggerDict:
        if logger_name.startswith("absa."):
            logger = logging.getLogger(logger_name)
            logger.setLevel(log_level)

    root_absa = logging.getLogger("absa")
    root_absa.setLevel(log_level)