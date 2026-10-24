from app.mfa.strategies.backup_code_strategy import BackupCodeStore, BackupCodeStrategy
from app.mfa.strategies.base import MFAMethod, SecondFactorStrategy
from app.mfa.strategies.totp_strategy import SecretProvider, TOTPStrategy


class UnknownMFAMethod(ValueError):
    pass


def build_strategy(
    method: MFAMethod | str,
    *,
    secret_provider: SecretProvider,
    backup_store: BackupCodeStore,
) -> SecondFactorStrategy:
    try:
        method = MFAMethod(method)
    except ValueError:
        raise UnknownMFAMethod(f"unknown MFA method: {method!r}") from None

    match method:
        case MFAMethod.TOTP:
            return TOTPStrategy(secret_provider)
        case MFAMethod.BACKUP:
            return BackupCodeStrategy(backup_store)
