using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Otp.Data.Services;
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
            Error = GetError(outcome, _passwordLoginOptions.DetailedErrors),
            MaskedEmail = MaskEmail(request.Email),
        };

        if (outcome == OtpRequestOutcome.CodeSent)
        {
            await delayedResponse.SucceedAsync();
        }
        else
        {
            await delayedResponse.FailAsync();
        }

        return Ok(result);
    }

    private static IdentityError GetError(OtpRequestOutcome outcome, bool detailedErrors)
    {
        // Outcomes that reveal whether the user exists are reported only when detailed errors are enabled.
        return outcome switch
        {
            OtpRequestOutcome.CodeSent => null,
            OtpRequestOutcome.StoreNotFound => OtpErrorDescriber.StoreNotFound(),
            OtpRequestOutcome.OtpDisabled => OtpErrorDescriber.OtpDisabled(),
            OtpRequestOutcome.UserNotFound when detailedErrors => OtpErrorDescriber.UserNotFound(),
            OtpRequestOutcome.UserNotFound => null,
            OtpRequestOutcome.DuplicateEmail when detailedErrors => OtpErrorDescriber.DuplicateEmail(),
            OtpRequestOutcome.DuplicateEmail => null,
            OtpRequestOutcome.LockoutDisabled when detailedErrors => OtpErrorDescriber.LockoutDisabled(),
            OtpRequestOutcome.LockoutDisabled => null,
            OtpRequestOutcome.StoreAccessDenied when detailedErrors => OtpErrorDescriber.StoreAccessDenied(),
            OtpRequestOutcome.StoreAccessDenied => null,
            _ => OtpErrorDescriber.LoginFailed(),
        };
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
