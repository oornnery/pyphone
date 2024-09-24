import logging
from rich.logging import RichHandler
from rich.console import Console

cl = Console()

logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=cl)],
)

log = logging.getLogger("rich")
