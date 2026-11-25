"""Provider adapters: fetch headers only, read-only, and return provider-neutral MessageMeta."""


class ProviderError(Exception):
    """The mail provider refused a request (shown to the user without a traceback)."""
