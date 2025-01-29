import typer
from rich.console import Console

app = typer.Typer()
console = Console()

@app.command()
def call(number: str):
    console.print(f"Calling {number}")

@app.command()
def register(
    username: str = typer.Argument(..., help="Username"),
    password: str = typer.Argument(..., help="Password"),
    domain: str = typer.Option(None, help="Proxy server"),
    port: int = typer.Option(5060, help="Port number"),
    display_name: str = typer.Option(None, help="Display name"),
    proxy: str = typer.Option(None, help="Proxy server"),
):
    console.print(f"Registering {username} with {domain}{':' if port else ''}{port}")

if __name__ == "__main__":
    app()