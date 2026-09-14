namespace VirtoCommerce.Otp.Core.Models;

public class OtpVerifyResult
{
    public OtpVerifyOutcome Outcome { get; set; }

    /// <summary>
    /// Populated only for <see cref="OtpVerifyOutcome.AccountLocked"/> — seconds remaining until the platform's
    /// standard account lockout (shared with password sign-in) clears.
    /// </summary>
    public int? LockoutSecondsRemaining { get; set; }
}
