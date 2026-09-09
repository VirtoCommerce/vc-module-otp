using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using VirtoCommerce.Platform.Core.Security.ExternalSignIn;

namespace VirtoCommerce.Otp.Web.Security;

/// <summary>
/// Establishes a pending external login (the same cookie an OAuth provider would set after a successful
/// challenge/callback round-trip) once an OTP code has been verified. This lets the platform's existing
/// IExternalSignInService/`external_sign_in` grant type finish the sign-in without any changes to the
/// platform's token pipeline. It intentionally does not implement IExternalSignInService itself: that
/// interface has a single active DI registration, and replacing it here would break the existing
/// Google/AzureAD sign-in providers.
/// </summary>
public class OtpExternalSignInService
{
    public async Task SignInAsync(HttpContext httpContext, string storeId, string email)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, email),
            new(ClaimTypes.Email, email),
            new(ClaimTypes.Name, email),
        };

        var identity = new ClaimsIdentity(claims, IdentityConstants.ExternalScheme);
        var principal = new ClaimsPrincipal(identity);

        var authenticationProperties = new AuthenticationProperties
        {
            Items = { ["LoginProvider"] = OtpExternalSignInProvider.AuthenticationType },
        };
        authenticationProperties.SetStoreId(storeId);

        await httpContext.SignInAsync(IdentityConstants.ExternalScheme, principal, authenticationProperties);
    }
}
