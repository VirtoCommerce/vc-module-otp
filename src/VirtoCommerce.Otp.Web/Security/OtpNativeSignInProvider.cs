using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Security.NativeSignIn;

namespace VirtoCommerce.Otp.Web.Security;

/// <summary>
/// Completes an OTP sign-in for the platform's "native_sign_in" token grant. Verifies the emailed
/// code itself (via <see cref="IOtpService"/>) and hands back the exact user it belongs to — no
/// external-login cookie, no pretending to be an OAuth provider.
/// </summary>
public class OtpNativeSignInProvider : INativeSignInProvider
{
    public const string ProviderName = "OTP";

    private readonly IOtpService _otpService;
    private readonly UserManager<ApplicationUser> _userManager;

    public OtpNativeSignInProvider(IOtpService otpService, UserManager<ApplicationUser> userManager)
    {
        _otpService = otpService;
        _userManager = userManager;
    }

    public string Name => ProviderName;

    public async Task<ApplicationUser> ValidateAsync(OpenIddictRequest request)
    {
        var storeId = (string)request.GetParameter("storeId");
        var email = ((string)request.GetParameter("email"))?.Trim();
        var code = (string)request.GetParameter("code");

        if (string.IsNullOrEmpty(storeId) || string.IsNullOrEmpty(email) || string.IsNullOrEmpty(code))
        {
            return null;
        }

        var result = await _otpService.VerifyCodeAsync(storeId, email, code);
        if (result.Outcome != OtpVerifyOutcome.Success)
        {
            return null;
        }

        return await _userManager.FindByEmailAsync(email);
    }
}
