using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Platform.Core.Events;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Core.Security.SignInLog;
using VirtoCommerce.Platform.Security.OpenIddict;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace VirtoCommerce.Otp.Data.Services;

/// <summary>
/// Handles the "otp_email" token grant: verifies the emailed code via <see cref="IOtpService"/>
/// and signs in the matching user.
/// </summary>
public class OtpGrantTypeHandler : GrantTypeHandlerBase
{
    private readonly IOtpService _otpService;

    public OtpGrantTypeHandler(
        IOtpService otpService,
        SignInManager<ApplicationUser> signInManager,
        IOptions<IdentityOptions> identityOptions,
        IEnumerable<ITokenRequestValidator> requestValidators,
        IEnumerable<ITokenClaimProvider> claimProviders,
        IEnumerable<ITokenRequestHandler> requestHandlers,
        IEventPublisher eventPublisher)
        : base(signInManager, identityOptions, requestValidators, claimProviders, requestHandlers, eventPublisher)
    {
        _otpService = otpService;
    }

    public override string GrantType => ModuleConstants.Security.GrantType;

    protected override string SignInType => "OTP";

    protected override async Task<GrantValidationResult> ValidateGrantAsync(TokenRequestContext context)
    {
        var verifyResult = await VerifyAsync(context.Request);
        if (verifyResult.Outcome != OtpVerifyOutcome.Success)
        {
            context.FailureReason = GetFailureReason(verifyResult.Outcome);

            return GrantValidationResult.Fail(BuildErrorResponse(verifyResult, context.DetailedErrors));
        }

        return GrantValidationResult.Succeed(verifyResult.User);
    }

    private async Task<OtpVerifyResult> VerifyAsync(OpenIddictRequest request)
    {
        var email = (string)request.GetParameter("email");
        var code = (string)request.GetParameter("code");
        var storeId = (string)request.GetParameter("storeId");

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(code))
        {
            return new OtpVerifyResult { Outcome = OtpVerifyOutcome.InvalidCode };
        }

        return await _otpService.VerifyCodeAsync(email, code, storeId);
    }

    private static string GetFailureReason(OtpVerifyOutcome outcome)
    {
        return outcome switch
        {
            OtpVerifyOutcome.AccountLocked => SignInFailureReason.LockedOut,
            OtpVerifyOutcome.OtpDisabled => ModuleConstants.Security.FailureReason.OtpDisabled,
            _ => ModuleConstants.Security.FailureReason.InvalidCode,
        };
    }

    private static TokenResponse BuildErrorResponse(OtpVerifyResult verifyResult, bool detailedErrors)
    {
        return verifyResult.Outcome switch
        {
            OtpVerifyOutcome.AccountLocked when detailedErrors => new TokenResponse
            {
                Error = Errors.InvalidGrant,
                Code = "account_locked",
                ErrorDescription = "Too many incorrect attempts. Please try again later.",
                LockoutSecondsRemaining = verifyResult.LockoutSecondsRemaining,
            },
            OtpVerifyOutcome.OtpDisabled when detailedErrors => new TokenResponse
            {
                Error = Errors.InvalidGrant,
                Code = "otp_disabled",
                ErrorDescription = "OTP sign-in is disabled for this store.",
            },
            _ => new TokenResponse
            {
                Error = Errors.InvalidGrant,
                Code = "invalid_code",
                ErrorDescription = "The code is invalid or has expired.",
            },
        };
    }
}
