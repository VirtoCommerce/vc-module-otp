using Newtonsoft.Json;
using VirtoCommerce.Platform.Core.Security;

namespace VirtoCommerce.Otp.Core.Models;

public class OtpVerifyResult
{
    public OtpVerifyOutcome Outcome { get; set; }

    /// <summary>
    /// Set only for <see cref="OtpVerifyOutcome.AccountLocked"/>: seconds until the lockout clears.
    /// </summary>
    public int? LockoutSecondsRemaining { get; set; }

    /// <summary>
    /// Set only for <see cref="OtpVerifyOutcome.Success"/>. Not serialized - this result is also
    /// returned as-is from the public /api/otp/verify endpoint.
    /// </summary>
    [JsonIgnore]
    public ApplicationUser User { get; set; }
}
