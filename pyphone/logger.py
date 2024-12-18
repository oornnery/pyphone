import logging
from rich.logging import RichHandler

logging.basicConfig(
    filename='logs/sip_client.log',
    filemode='w',
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

logger = logging.getLogger("rich")
