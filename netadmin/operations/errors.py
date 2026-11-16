"""Trusted operation error codes; native/library diagnostics stay private."""

MESSAGES = {
    "boundary_missing": "Install the trusted operation boundary before invoking this CLI",
    "boundary_invalid": "Operation boundary must be an absolute, dedicated path",
    "boundary_mismatch": "Argument does not match the configured operation boundary",
    "relative_unsafe": "Unsafe or unrelated credential-store path",
    "selection_symlink": "Operation selection may not follow a symlink",
    "selection_missing": "Operation selection is unavailable",
    "destination_invalid": "Destination is outside the configured operation boundary",
    "source_changed": "Backup source changed during capture",
    "password_length": "Recovery passphrase must contain 16-1024 bytes",
    "password_file": "Recovery passphrase file must be a private regular file "
    "owned by the operator",
    "selection_limit": "Backup selection is empty or too large",
    "source_type": "Backup sources may not contain links or special files",
    "capture_limit": "Backup exceeds its safety limit; partition the selection",
    "quiescence": "Stop all writers first and confirm --quiesced",
    "archive_location": "Store backup archives outside the source tree",
    "archive_extension": "Use an encrypted backup archive",
    "archive_type": "Encrypted archive is not a bounded regular file",
    "archive_limit": "Encrypted archive exceeds its size limit",
    "archive_format": "Unsupported backup format",
    "authentication": "Backup authentication failed",
    "restore_limit": "Backup exceeds restoration limits",
    "member_parent": "Backup member has an unsafe parent or size",
    "member_type": "Backup contains duplicate, linked or special members",
    "member_incomplete": "Backup member is incomplete",
    "root_required": "--root is required",
    "target_required": "--target must name a new directory",
}


class OperationInputError(ValueError):
    """Only fixed messages for independently validated operator input errors."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(self.public_message())

    def public_message(self) -> str:
        """Never echo unknown codes or exception arguments."""
        return MESSAGES.get(self.code, "Operation input is invalid; check the supplied settings")
