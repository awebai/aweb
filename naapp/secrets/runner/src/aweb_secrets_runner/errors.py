class Refused(Exception):
    """A fixed, value-free refusal suitable for the command's stderr."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)
