using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.StoreModule.Core.Model;

namespace VirtoCommerce.Otp.Core.Models;

public class OtpResult
{
    public OtpOutcome Outcome { get; set; }

    public Store Store { get; set; }

    public ApplicationUser User { get; set; }

    public static OtpResult Succeed(Store store, ApplicationUser user)
    {
        return new OtpResult
        {
            Outcome = OtpOutcome.Success,
            Store = store,
            User = user,
        };
    }

    public static OtpResult Fail(OtpOutcome outcome, Store store = null, ApplicationUser user = null)
    {
        return new OtpResult
        {
            Outcome = outcome,
            Store = store,
            User = user,
        };
    }
}
