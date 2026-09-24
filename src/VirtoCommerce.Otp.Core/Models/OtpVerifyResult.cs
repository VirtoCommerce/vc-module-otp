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

    [JsonIgnore]
    public ApplicationUser User { get; set; }
}
