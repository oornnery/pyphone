import typer

app = typer.Typer()

@app.command()
def register():
    pass

@app.command()
def invite():
    pass

@app.command()
def options():
    pass

@app.command()
def request():
    pass

@app.command()
def response():
    pass



if __name__ == "__main__":
    app()