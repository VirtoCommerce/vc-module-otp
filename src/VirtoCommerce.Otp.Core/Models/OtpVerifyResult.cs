using System.Text.Json.Serialization;

namespace VirtoCommerce.Otp.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum OtpVerifyOutcome
{
    Success,
    InvalidCode,
    Disabled,
    Locked,
}

public class OtpVerifyResult
{
    public OtpVerifyOutcome Outcome { get; set; }

    /// <summary>
    /// Populated only for <see cref="OtpVerifyOutcome.Locked"/> — seconds remaining until the platform's
    /// standard account lockout (shared with password sign-in) clears.
    /// </summary>
    public int? LockoutSecondsRemaining { get; set; }
}
