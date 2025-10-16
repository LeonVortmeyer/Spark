import logging
import coloredlogs
from typing import Optional


def setup_logger(
    name: Optional[str] = None,
    level: str = "INFO",
    format_string: Optional[str] = None
) -> logging.Logger:
    """
    Set up a logger with coloredlogs formatting.

    Args:
        name: Logger name (defaults to calling module name)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_string: Custom format string (optional)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name or __name__)

    if not format_string:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    coloredlogs.install(
        level=level,
        logger=logger,
        fmt=format_string,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance. If not already configured, sets it up with defaults.

    Args:
        name: Logger name (defaults to calling module name)

    Returns:
        Logger instance
    """
    logger = logging.getLogger(name or __name__)

    if not logger.handlers:
        return setup_logger(name)

    return logger
