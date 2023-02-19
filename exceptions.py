class RegisterError(Exception):
    """
    Exceptions raised for the register user widget.

    Attributes
    ----------
    message: str
        The custom error message to display.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)
