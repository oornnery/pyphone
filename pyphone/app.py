from textual import on
from textual.app import App, ComposeResult
from textual.events import Key
from textual.containers import ScrollableContainer, Container, Grid, Horizontal, HorizontalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Footer,
    Header,
    Button,
    Label,
    Static,
    Input,
    ListItem,
    ListView,
    Static,
    )

class Account:
    def __init__(self, username, display, password, domain, port):
        self.username = username
        self.display = display
        self.password = password
        self.domain = domain
        self.port = port

    def __repr__(self):
        return f"Account({self.username}, {self.display}, {self.password}, {self.domain}, {self.port})"

class ScreenContainer(ModalScreen):
    BINDINGS = [("escape", "pop_screen")]

class AccountSettingsScreen(ScreenContainer):
    def compose(self) -> ComposeResult:
        with Container():
            yield Label("Account Settings")

            with Container() as input_container:
                yield Input(placeholder="Username: ", id="username")
                yield Input(placeholder="Display: ", id="display")
                yield Input(placeholder="Password: ", id="password")
                yield Input(placeholder="Domain: ", id="domain")
                yield Input(placeholder="Port: ", id="port")

            yield Button("Save", id="btn-save-account", variant="success")

    @on(Button.Pressed, "#btn-save-account")
    def on_btn_save_account(self, event: Button.Pressed):
        username = self.query_one("#username").value
        display = self.query_one("#display").value
        password = self.query_one("#password").value
        domain = self.query_one("#domain").value
        port = self.query_one("#port").value
        account = Account(username, display, password, domain, port)
        self.dismiss(account)


class AccountsScreen(ScreenContainer):
    def compose(self) -> ComposeResult:
        with Container():
            yield Label("Accounts")
            with ListView(classes="accounts-list") as list_view:
                for i in range(10):
                    yield ListItem(Static(f"Account {i}"), classes="account-item")
            yield Button("Add", id="btn-add-account", variant="success")
            
    @on(Button.Pressed, "#btn-add-account")
    def on_btn_add_account(self, event: Button.Pressed):
        self.app.push_screen(AccountSettingsScreen(), callback=self.modal_callback_to_account_settings)
    
    def modal_callback_to_account_settings(self, account):
        self.query_one(".accounts-list").append(ListItem(Static(f"Account {account.display}")))


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


class Sidebar(Container):
    BINDINGS = [("escape", "toggle_sidebar")]



class PyPhone(App[None]):
    CSS_PATH = "style.tcss"
    AUTO_FOCUS = "#display-num"
    BINDINGS = [
        ("a", "get_accounts", "Accounts"),
        ("ctrl+s", "toggle_sidebar"),
        ("f1", "get_help", "Help"),
        ("q", "quit", "Quit"),
        ]
    
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True, name="PyPhone")
        with Container(id='root') as root:
            with Sidebar(classes="-hidden"):
                yield Button("Accounts", classes="btn-sidebar", id="btn-accounts")
                yield Button("Help", classes="btn-sidebar", id="btn-help")
                yield Button("Quit", classes="btn-sidebar", id="btn-quit")
            yield Display()
            yield Keypad()
        yield Footer()

    def action_toggle_sidebar(self) -> None:
        self.query_one(Sidebar).toggle_class("-hidden")

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

    @on(Key("escape", None), 'Sidebar')
    def on_escape(self):
        self.action_toggle_sidebar()

    @on(Button.Pressed, '.btn-sidebar')
    def on_btn_quit(self, event: Button.Pressed):
        button_id = event.button.id
        if button_id == "btn-accounts":
            self.action_get_accounts()
        elif button_id == "btn-help":
            self.action_get_help()
        elif button_id == "btn-quit":
            self.action_quit()

if __name__ == "__main__":
    app = PyPhone()
    app.run()