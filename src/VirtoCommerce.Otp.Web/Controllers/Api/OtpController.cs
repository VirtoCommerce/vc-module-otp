using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Platform.Core.Security;

namespace VirtoCommerce.Otp.Web.Controllers.Api;

[ApiController]
[Route("api/otp")]
[AllowAnonymous]
public class OtpController : Controller
{
    private readonly IOtpService _otpService;
    private readonly PasswordLoginOptions _passwordLoginOptions;

    public OtpController(IOtpService otpService, IOptions<PasswordLoginOptions> passwordLoginOptions)
    {
        _otpService = otpService;
        _passwordLoginOptions = passwordLoginOptions.Value;
    }

    [HttpPost]
    [Route("request")]
    public async Task<ActionResult<OtpRequestResult>> RequestCode([FromBody] OtpRequest request)
    {
        var delayedResponse = DelayedResponse.Create(nameof(OtpController), nameof(RequestCode));

        var result = await _otpService.RequestCodeAsync(request.Email, request.StoreId);

        if (result.Outcome == OtpRequestOutcome.OtpDisabled)
        {
            await delayedResponse.FailAsync();

            if (!_passwordLoginOptions.DetailedErrors)
            {
                result.Outcome = OtpRequestOutcome.CodeSent;
            }
        }
        else
        {
            await delayedResponse.SucceedAsync();
        }

        return Ok(result);
    }
}
