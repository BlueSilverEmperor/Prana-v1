"""Adapter error types. Kept free of engine imports so the API starts in mock mode
even when the Vero engine packages are not installed."""


class EngineInputError(ValueError):
    """The request failed the engine's input validation (address, hex, integer format)."""
