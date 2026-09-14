using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Otp.Web.Models;

namespace VirtoCommerce.Otp.Web.Controllers.Api;

// Verification here is purely for the storefront's UX (rich per-outcome feedback: invalid code,
// locked, disabled). Completing the actual sign-in is a separate step: the client sends the same
// email/code to POST /connect/token with grant_type=native_sign_in&provider=OTP, handled by
// OtpNativeSignInProvider. Re-verifying there is safe: a code is not consumed by checking it.
[ApiController]
[Route("api/otp")]
[AllowAnonymous]
public class OtpController : Controller
{
    private readonly IOtpService _otpService;

    public OtpController(IOtpService otpService)
    {
        _otpService = otpService;
    }

    [HttpPost]
    [Route("request")]
    public async Task<ActionResult<OtpRequestResult>> RequestCode([FromBody] OtpRequestCodeRequest request)
    {
        var result = await _otpService.RequestCodeAsync(request.StoreId, request.Email);
        return Ok(result);
    }

    [HttpPost]
    [Route("verify")]
    public async Task<ActionResult<OtpVerifyResult>> VerifyCode([FromBody] OtpVerifyCodeRequest request)
    {
        var email = request.Email?.Trim();
        var result = await _otpService.VerifyCodeAsync(request.StoreId, email, request.Code);

        return Ok(result);
    }
}
