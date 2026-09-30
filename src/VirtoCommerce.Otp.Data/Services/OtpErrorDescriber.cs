using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;
using VirtoCommerce.Platform.Security.OpenIddict;

namespace VirtoCommerce.Otp.Data.Services;

public static class OtpErrorDescriber
{
    public static IdentityError MissingParameters(IEnumerable<string> parameters) => new()
    {
        Code = "missing_parameter",
        Description = $"Missing required parameters: {string.Join(", ", parameters)}.",
    };

    public static IdentityError StoreNotFound() => new()
    {
        Code = "store_not_found",
        Description = "The store was not found.",
    };

    public static IdentityError OtpDisabled() => new()
    {
        Code = "otp_disabled",
        Description = "OTP sign-in is disabled for this store.",
    };

    public static IdentityError UserNotFound() => new()
    {
        Code = "user_not_found",
        Description = "No user with this email was found.",
    };

    public static IdentityError DuplicateEmail() => ToIdentityError(SecurityErrorDescriber.DuplicateEmailLoginAttempt());

    public static IdentityError LoginFailed() => ToIdentityError(SecurityErrorDescriber.LoginFailed());

    public static IdentityError LockoutDisabled() => new()
    {
        Code = "lockout_disabled",
        Description = "OTP sign-in is not available for accounts without lockout protection.",
    };

    public static IdentityError AccountLocked() => new()
    {
        Code = "account_locked",
        Description = "Too many incorrect attempts. Please try again later.",
    };

    public static IdentityError StoreAccessDenied() => new()
    {
        Code = "user_cannot_login_in_store",
        Description = "Access denied. You cannot sign in to the current store",
    };

    public static IdentityError InvalidCode() => new()
    {
        Code = "invalid_code",
        Description = "The code is invalid or has expired.",
    };

    private static IdentityError ToIdentityError(TokenResponse response) => new()
    {
        Code = response.Code,
        Description = response.ErrorDescription,
    };
}
