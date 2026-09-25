namespace VirtoCommerce.Otp.Core.Models;

public enum OtpRequestOutcome
{
    Undefined,
    CodeSent,
    StoreNotFound,
    OtpDisabled,
    UserNotFound,
    DuplicateEmail,
    LockoutDisabled,
    StoreAccessDenied,
}
