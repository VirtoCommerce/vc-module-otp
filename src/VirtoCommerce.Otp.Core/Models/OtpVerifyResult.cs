using VirtoCommerce.Platform.Core.Security;

namespace VirtoCommerce.Otp.Core.Models;

public class OtpVerifyResult
{
    public OtpVerifyOutcome Outcome { get; set; }

    public ApplicationUser User { get; set; }

    public static OtpVerifyResult Succeed(ApplicationUser user)
    {
        return new OtpVerifyResult
        {
            Outcome = OtpVerifyOutcome.Success,
            User = user,
        };
    }

    public static OtpVerifyResult Fail(OtpVerifyOutcome outcome, ApplicationUser user = null)
    {
        return new OtpVerifyResult
        {
            Outcome = outcome,
            User = user,
        };
    }
}
