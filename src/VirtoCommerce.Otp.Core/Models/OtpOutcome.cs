namespace VirtoCommerce.Otp.Core.Models;

public enum OtpOutcome
{
    Undefined,
    Success,
    StoreNotFound,
    OtpDisabled,
    UserNotFound,
    DuplicateEmail,
    LockoutDisabled,
    AccountLocked,
    InvalidCode,
    StoreAccessDenied,
}
