import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

formatter = logging.Formatter('%(levelname)s: %(message)s')
ch.setFormatter(formatter)

logger.addHandler(ch)

def log_error(*args, **kwargs):
    logger.error(*args, **kwargs)

def log_info(*args, **kwargs):
    logger.info(*args, **kwargs)

def log_warn(*args, **kwargs):
    logger.warn(*args, **kwargs)

def log_debug(*args, **kwargs):
    logger.debug(*args, **kwargs)
