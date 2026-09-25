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
public class OtpController(
    IOtpService otpService,
    IOptions<PasswordLoginOptions> passwordLoginOptions)
    : Controller
{
    private readonly PasswordLoginOptions _passwordLoginOptions = passwordLoginOptions.Value;

    [HttpPost]
    [Route("request")]
    public async Task<ActionResult<OtpRequestResult>> RequestCode([FromBody] OtpRequest request)
    {
        var delayedResponse = DelayedResponse.Create(nameof(OtpController), nameof(RequestCode));
        var outcome = await otpService.RequestCodeAsync(request.StoreId, request.Email);

        var result = new OtpRequestResult
        {
            Outcome = outcome,
            MaskedEmail = MaskEmail(request.Email),
        };

        if (outcome == OtpRequestOutcome.CodeSent)
        {
            await delayedResponse.SucceedAsync();
        }
        else
        {
            if (!_passwordLoginOptions.DetailedErrors &&
                outcome is
                    OtpRequestOutcome.UserNotFound or
                    OtpRequestOutcome.DuplicateEmail or
                    OtpRequestOutcome.LockoutDisabled or
                    OtpRequestOutcome.StoreAccessDenied)
            {
                result.Outcome = OtpRequestOutcome.CodeSent;
            }

            await delayedResponse.FailAsync();
        }

        return Ok(result);
    }

    protected virtual string MaskEmail(string email)
    {
        var atIndex = email.IndexOf('@');
        if (atIndex <= 1)
        {
            return email;
        }

        var localPart = email[..atIndex];
        var domainPart = email[atIndex..];

        return $"{localPart[0]}•••{localPart[^1]}{domainPart}";
    }
}
