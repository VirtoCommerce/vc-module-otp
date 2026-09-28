using VirtoCommerce.Platform.Core.Security;

namespace VirtoCommerce.Otp.Core.Models;

public class OtpVerifyResult
{
    public OtpVerifyOutcome Outcome { get; set; }

    public int? LockoutSecondsRemaining { get; set; }

    public ApplicationUser User { get; set; }
}
