"""Shared rotating log configuration for local retrieval."""

import os
import logging
from logging.handlers import RotatingFileHandler

def setup_logging(log_dir: str = None, log_level: int = logging.INFO):
    """Configure rotating local log files."""
    
    if log_dir is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_dir = os.path.join(base_dir, "logs")

    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, "protocol_fuzzer.log")

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    root_logger.handlers.clear()

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(log_level)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)

    root_logger.addHandler(file_handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return root_logger

def get_logger(name: str) -> logging.Logger:
    """Return a named logger."""
    return logging.getLogger(name)

setup_logging()
