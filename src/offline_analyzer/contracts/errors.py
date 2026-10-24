"""Fixed local operation errors shared across ingestion and provenance boundaries."""


class InputError(ValueError):
    def __init__(
        self,
        code: str,
        *,
        limit: dict[str, int | str] | None = None,
        identity_context: dict[str, str] | None = None,
    ):
        super().__init__(code)
        self.limit = limit
        # Session-only operator detail. Never included in str(exc), logs or journals.
        self.identity_context = identity_context
