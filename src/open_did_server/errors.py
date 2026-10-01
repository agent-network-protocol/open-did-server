"""HTTP errors for the reference server."""


class ApiError(Exception):
    """A finished API failure with a stable error code."""

    def __init__(
        self,
        status: int,
        error: str,
        message: str,
        *,
        www_authenticate: str | None = None,
        accept_signature: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.error = error
        self.message = message
        self.www_authenticate = www_authenticate
        self.accept_signature = accept_signature


def auth_error(anp_error: str, message: str, *, realm: str, accept_signature: str) -> ApiError:
    """Build a 401 that carries the ANP-02 DIDWba challenge."""
    challenge = (
        f'DIDWba realm="{realm}", error="{anp_error}", error_description="{_challenge_text(message)}"'
    )
    return ApiError(
        401,
        anp_error,
        message,
        www_authenticate=challenge,
        accept_signature=accept_signature,
    )


def _challenge_text(message: str) -> str:
    return message.replace("\\", "\\\\").replace('"', "'")
