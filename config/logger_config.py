import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = Path(__file__).parents[1] / "logs"

def setup_logger(level: int = logging.INFO) -> None:
    formatter=logging.Formatter(fmt="%(asctime)s | %(levelname)-8s | %(name)-22s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    console_handler=logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    log_file_handler= RotatingFileHandler(LOG_DIR / "scanner.log", maxBytes=1024*1024*10,encoding="utf-8", backupCount=5)
    log_file_handler.setFormatter(formatter)
    log_file_handler.setLevel(logging.DEBUG)

    error_handler=RotatingFileHandler(LOG_DIR / "errors.log", maxBytes=1024*1024*10, encoding="utf-8", backupCount=5)
    error_handler.setFormatter(formatter)
    error_handler.setLevel(logging.ERROR)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(log_file_handler)
    root_logger.addHandler(error_handler)
