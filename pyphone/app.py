from textual import on
from textual.app import App, ComposeResult
from textual.containers import ScrollableContainer, Container, Grid, Horizontal, HorizontalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Footer,
    Header,
    Button,
    Label,
    Static,
    Input,
    )


class ScreenContainer(ModalScreen):
    BINDINGS = [("escape", "pop_screen")]

class AccountsScreen(ScreenContainer):
    def compose(self) -> ComposeResult:
        with Container():
            yield Label("Accounts")


class Display(Container):
    def compose(self) -> ComposeResult:
        yield Input(placeholder='Enter a number: ', id="display-num")
        yield Label("", id="display-log", expand=True)


class Keypad(ScrollableContainer):
    def compose(self) -> ComposeResult:
        for n in range(1, 10):
            yield Button(f"{n}",name=f"{n}", classes='keypad-button')
        yield Button("*", name='*', classes='keypad-button')
        yield Button("0", name='0', classes='keypad-button')
        yield Button("#", name='#', classes='keypad-button')
        redial_button = Button("R", name='R', classes='keypad-button')
        redial_button.tooltip = "Redial"
        yield redial_button
        yield Button("+", name='+', classes='keypad-button')
        clear_button = Button("C", name='C', classes='keypad-button')
        clear_button.tooltip = "Clear"
        yield clear_button
        yield Button("Enter", name='E', classes='keypad-button', id='keypad-enter', variant='success')


class HelpScreen(ScreenContainer):
    DEFAULT_CSS = """
    #help-screen-container {
        & > Label#exit {
            margin-top: 1;
        }
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="help-screen-container"):
            yield Label("This is the help screen.")
            yield Label("You've been helped.")
            yield Label("Press ESC to exit.", id="exit")


class ExitScreen(ScreenContainer):
    DEFAULT_CSS = """

    ExitScreen > Container > Label {
        width: 100%;
        content-align-horizontal: center;
    }

    ExitScreen > Container > Horizontal {
        height: auto;
        width: auto;
    }

    ExitScreen > Container > Horizontal > Button {
        margin: 1 2;
    }
    """
    def compose(self):
        with Container():
            yield Label("Exit PyPhone?")
            with Horizontal():
                yield Button.success("Yes", id="yes")
                yield Button.error("No", id="no")

    @on(Button.Pressed)
    def exit_screen(self, event):
        button_id = event.button.id
        self.dismiss(button_id == "yes")



class PyPhone(App[None]):
    CSS_PATH = "style.tcss"
    AUTO_FOCUS = "#display-num"
    BINDINGS = [
        ("a", "get_accounts", "Accounts"),
        ("f1", "get_help", "Help"),
        ("q", "quit", "Quit"),
        ]
    
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True, name="PyPhone")
        with Container(id='root') as root:
            yield Display()
            yield Keypad()
        yield Footer()

    def action_get_accounts(self) -> None:
        self.push_screen(AccountsScreen())
    
    def action_get_help(self) -> None:
        self.push_screen(HelpScreen())
    
    def action_quit(self):
        self.push_screen(ExitScreen(), callback=self.modal_callback_to_exit)

    def modal_callback_to_exit(self, should_exit):
        if should_exit:
            self.exit()
    
    @on(Button.Pressed, '.keypad-button')
    def on_button_pressed_keypad(self, event: Button.Pressed) -> None:
        print(event.button.name)
        query = self.query_one(Display)
        query_input = query.query_one(Input)
        if event.button.name == 'C':
            query_input.value = ''
            return
        elif event.button.name == 'E':
            query_log = query.query_one('#display-log')
            query_log.update(f"[green]Calling[/green] {query_input.value}")
            return
        query_input.value = query_input.value + event.button.name

if __name__ == "__main__":
    app = PyPhone()
    app.run()