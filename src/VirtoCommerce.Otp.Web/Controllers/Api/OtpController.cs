using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Otp.Web.Models;
using VirtoCommerce.Otp.Web.Security;

namespace VirtoCommerce.Otp.Web.Controllers.Api;

[ApiController]
[Route("api/otp")]
[AllowAnonymous]
public class OtpController : Controller
{
    private readonly IOtpService _otpService;
    private readonly OtpExternalSignInService _otpExternalSignInService;

    public OtpController(IOtpService otpService, OtpExternalSignInService otpExternalSignInService)
    {
        _otpService = otpService;
        _otpExternalSignInService = otpExternalSignInService;
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
        var email = request.Email?.Trim().ToLowerInvariant();
        var result = await _otpService.VerifyCodeAsync(request.StoreId, email, request.Code);

        if (result.Outcome == OtpVerifyOutcome.Success)
        {
            await _otpExternalSignInService.SignInAsync(HttpContext, request.StoreId, email);
        }

        return Ok(result);
    }
}
