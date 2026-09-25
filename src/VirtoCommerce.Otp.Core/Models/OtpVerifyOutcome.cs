namespace VirtoCommerce.Otp.Core.Models;

public enum OtpVerifyOutcome
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
