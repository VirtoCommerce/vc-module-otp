using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using VirtoCommerce.Platform.Security.ExternalSignIn;

namespace VirtoCommerce.Otp.Web.Security;

public class OtpExternalSignInProvider : IExternalSignInProvider
{
    public const string AuthenticationType = "Otp";

    public int Priority => 0;

    public bool HasLoginForm => false;

    // OTP sign-in is only for returning users; unknown emails are not auto-provisioned.
    public bool AllowCreateNewUser => false;

    public string GetUserName(ExternalLoginInfo externalLoginInfo)
    {
        return externalLoginInfo.Principal.FindFirstValue(ClaimTypes.Email);
    }

    public string GetUserType()
    {
        return "Customer";
    }

    public string[] GetUserRoles()
    {
        return [];
    }
}
