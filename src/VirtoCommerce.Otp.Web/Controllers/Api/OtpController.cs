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
        var codeRequestResult = await otpService.RequestCodeAsync(request.StoreId, request.Email);
        var detailedErrors = _passwordLoginOptions.DetailedErrors;
        var isLockoutReported = detailedErrors && codeRequestResult.Outcome == OtpOutcome.AccountLocked;

        var result = new OtpRequestResult
        {
            Error = GetError(codeRequestResult, detailedErrors),
            MaskedEmail = MaskEmail(request.Email),
            LockoutSecondsRemaining = isLockoutReported ? OtpErrorDescriber.GetLockoutSecondsRemaining(codeRequestResult.User) : null,
        };

        if (codeRequestResult.Outcome == OtpOutcome.Success)
        {
            await delayedResponse.SucceedAsync();
        }
        else
        {
            await delayedResponse.FailAsync();
        }

        return Ok(result);
    }

    private static IdentityError GetError(OtpResult codeRequestResult, bool detailedErrors)
    {
        // Outcomes that reveal whether the user exists are reported only when detailed errors are enabled.
        return codeRequestResult.Outcome switch
        {
            OtpOutcome.Success => null,
            OtpOutcome.StoreNotFound => OtpErrorDescriber.StoreNotFound(),
            OtpOutcome.OtpDisabled => OtpErrorDescriber.OtpDisabled(),
            OtpOutcome.UserNotFound when detailedErrors => OtpErrorDescriber.UserNotFound(),
            OtpOutcome.UserNotFound => null,
            OtpOutcome.DuplicateEmail when detailedErrors => OtpErrorDescriber.DuplicateEmail(),
            OtpOutcome.DuplicateEmail => null,
            OtpOutcome.LockoutDisabled when detailedErrors => OtpErrorDescriber.LockoutDisabled(),
            OtpOutcome.LockoutDisabled => null,
            OtpOutcome.AccountLocked when detailedErrors => OtpErrorDescriber.GetLockoutError(codeRequestResult.User),
            OtpOutcome.AccountLocked => null,
            OtpOutcome.StoreAccessDenied when detailedErrors => OtpErrorDescriber.StoreAccessDenied(),
            OtpOutcome.StoreAccessDenied => null,
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
