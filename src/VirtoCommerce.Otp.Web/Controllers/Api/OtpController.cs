using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;

namespace VirtoCommerce.Otp.Web.Controllers.Api;

// Verification here is only for storefront UX feedback; the actual sign-in happens via
// grant_type=email_otp_sign_in at /connect/token. Re-verifying is safe since checking a code doesn't consume it.
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
    public async Task<ActionResult<OtpRequestResult>> RequestCode([FromBody] EmailOtpRequestCodeRequest request)
    {
        var result = await _otpService.RequestCodeAsync(request.StoreId, request.Email);

        return Ok(result);
    }

    [HttpPost]
    [Route("verify")]
    public async Task<ActionResult<OtpVerifyResult>> VerifyCode([FromBody] EmailOtpVerifyCodeRequest request)
    {
        var result = await _otpService.VerifyCodeAsync(request.StoreId, request.Email, request.Code);

        return Ok(result);
    }
}
