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

public class OtpGrantTypeHandler(
    SignInManager<ApplicationUser> signInManager,
    IOptions<IdentityOptions> identityOptions,
    IEnumerable<ITokenRequestValidator> requestValidators,
    IEnumerable<ITokenClaimProvider> claimProviders,
    IEnumerable<ITokenRequestHandler> requestHandlers,
    IEventPublisher eventPublisher,
    IOtpService otpService)
    : GrantTypeHandlerBase(signInManager, identityOptions, requestValidators, claimProviders, requestHandlers, eventPublisher)
{
    public override string GrantType => ModuleConstants.Security.GrantType;

    protected override string SignInType => ModuleConstants.Security.SignInType;

    protected override async Task<GrantValidationResult> ValidateGrantAsync(TokenRequestContext context)
    {
        var missingParameters = new List<string>();

        var storeId = GetRequiredParameter(context.Request, ModuleConstants.Security.Parameters.StoreId, missingParameters);
        var email = GetRequiredParameter(context.Request, ModuleConstants.Security.Parameters.Email, missingParameters);
        var code = GetRequiredParameter(context.Request, ModuleConstants.Security.Parameters.Code, missingParameters);

        if (missingParameters.Count > 0)
        {
            return GrantValidationResult.Fail(BuildErrorResponse(context, missingParameters));
        }

        var verifyResult = await otpService.VerifyCodeAsync(storeId, email, code);
        context.SignInResult = GetSignInResult(verifyResult.Outcome);

        if (verifyResult.Outcome != OtpVerifyOutcome.Success)
        {
            return GrantValidationResult.Fail(BuildErrorResponse(context, verifyResult), verifyResult.User);
        }

        return GrantValidationResult.Succeed(verifyResult.User);
    }

    protected override UserSignInAttemptEvent BuildSignInAttemptEvent(TokenRequestContext context, bool succeeded)
    {
        var result = base.BuildSignInAttemptEvent(context, succeeded);
        result.UserName ??= (string)context.Request.GetParameter(ModuleConstants.Security.Parameters.Email);

        return result;
    }

    private static string GetRequiredParameter(OpenIddictRequest request, string name, List<string> missingParameters)
    {
        var value = (string)request.GetParameter(name);
        if (string.IsNullOrEmpty(value))
        {
            missingParameters.Add(name);
        }

        return value;
    }

    private static SignInResult GetSignInResult(OtpVerifyOutcome outcome)
    {
        return outcome switch
        {
            OtpVerifyOutcome.Success => SignInResult.Success,
            OtpVerifyOutcome.AccountLocked => SignInResult.LockedOut,
            _ => SignInResult.Failed,
        };
    }

    private static TokenResponse BuildErrorResponse(TokenRequestContext context, List<string> missingParameters)
    {
        context.FailureReason = ModuleConstants.Security.FailureReason.MissingParameter;

        return new TokenResponse
        {
            Error = Errors.InvalidRequest,
            Code = "missing_parameter",
            ErrorDescription = $"Missing required parameters: {string.Join(", ", missingParameters)}.",
        };
    }

    private static TokenResponse BuildErrorResponse(TokenRequestContext context, OtpVerifyResult verifyResult)
    {
        // The sign-in log always gets the real reason.
        context.FailureReason = verifyResult.Outcome switch
        {
            OtpVerifyOutcome.StoreNotFound => ModuleConstants.Security.FailureReason.StoreNotFound,
            OtpVerifyOutcome.OtpDisabled => ModuleConstants.Security.FailureReason.OtpDisabled,
            OtpVerifyOutcome.InvalidCode => ModuleConstants.Security.FailureReason.InvalidCode,
            OtpVerifyOutcome.UserNotFound => SignInFailureReason.UserNotFound,
            OtpVerifyOutcome.DuplicateEmail => SignInFailureReason.DuplicateEmail,
            OtpVerifyOutcome.LockoutDisabled => ModuleConstants.Security.FailureReason.LockoutDisabled,
            OtpVerifyOutcome.AccountLocked => SignInFailureReason.LockedOut,
            OtpVerifyOutcome.StoreAccessDenied => SignInFailureReason.Forbidden,
            _ => SignInFailureReason.Unknown,
        };

        // Outcomes that reveal whether the user exists are reported only when detailed errors are enabled.
        return verifyResult.Outcome switch
        {
            OtpVerifyOutcome.StoreNotFound => new TokenResponse
            {
                Error = Errors.InvalidRequest,
                Code = "store_not_found",
                ErrorDescription = "The store was not found.",
            },
            OtpVerifyOutcome.OtpDisabled => new TokenResponse
            {
                Error = Errors.InvalidGrant,
                Code = "otp_disabled",
                ErrorDescription = "OTP sign-in is disabled for this store.",
            },
            OtpVerifyOutcome.UserNotFound when context.DetailedErrors => new TokenResponse
            {
                Error = Errors.InvalidGrant,
                Code = "user_not_found",
                ErrorDescription = "No user with this email was found.",
            },
            OtpVerifyOutcome.DuplicateEmail when context.DetailedErrors => SecurityErrorDescriber.DuplicateEmailLoginAttempt(),
            OtpVerifyOutcome.LockoutDisabled when context.DetailedErrors => new TokenResponse
            {
                Error = Errors.InvalidGrant,
                Code = "lockout_disabled",
                ErrorDescription = "OTP sign-in is not available for accounts without lockout protection.",
            },
            OtpVerifyOutcome.AccountLocked when context.DetailedErrors => new TokenResponse
            {
                Error = Errors.InvalidGrant,
                Code = "account_locked",
                ErrorDescription = "Too many incorrect attempts. Please try again later.",
                LockoutSecondsRemaining = verifyResult.LockoutSecondsRemaining,
            },
            OtpVerifyOutcome.StoreAccessDenied => new TokenResponse
            {
                Error = Errors.InvalidGrant,
                Code = "user_cannot_login_in_store",
                ErrorDescription = "Access denied. You cannot sign in to the current store",
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
