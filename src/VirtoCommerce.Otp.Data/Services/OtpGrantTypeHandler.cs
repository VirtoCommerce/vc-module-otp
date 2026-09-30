using System;
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

        return CreateTokenResponse(Errors.InvalidRequest, OtpErrorDescriber.MissingParameters(missingParameters));
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
            OtpVerifyOutcome.StoreNotFound => CreateTokenResponse(Errors.InvalidRequest, OtpErrorDescriber.StoreNotFound()),
            OtpVerifyOutcome.OtpDisabled => CreateTokenResponse(Errors.InvalidGrant, OtpErrorDescriber.OtpDisabled()),
            OtpVerifyOutcome.UserNotFound when context.DetailedErrors => CreateTokenResponse(Errors.InvalidGrant, OtpErrorDescriber.UserNotFound()),
            OtpVerifyOutcome.DuplicateEmail when context.DetailedErrors => CreateTokenResponse(Errors.InvalidGrant, OtpErrorDescriber.DuplicateEmail()),
            OtpVerifyOutcome.LockoutDisabled when context.DetailedErrors => CreateTokenResponse(Errors.InvalidGrant, OtpErrorDescriber.LockoutDisabled()),
            OtpVerifyOutcome.AccountLocked when context.DetailedErrors => CreateTokenResponse(Errors.InvalidGrant, GetLockoutError(verifyResult.User), GetLockoutSecondsRemaining(verifyResult.User)),
            OtpVerifyOutcome.StoreAccessDenied => CreateTokenResponse(Errors.InvalidGrant, OtpErrorDescriber.StoreAccessDenied()),
            _ => CreateTokenResponse(Errors.InvalidGrant, OtpErrorDescriber.InvalidCode()),
        };
    }

    private static IdentityError GetLockoutError(ApplicationUser user)
    {
        return user.LockoutEnd == DateTime.MaxValue.ToUniversalTime()
            ? OtpErrorDescriber.UserIsLockedOut()
            : OtpErrorDescriber.UserIsTemporaryLockedOut();
    }

    private static int? GetLockoutSecondsRemaining(ApplicationUser user)
    {
        if (user.LockoutEnd is null)
        {
            return null;
        }

        var seconds = Math.Ceiling((user.LockoutEnd.Value - DateTimeOffset.UtcNow).TotalSeconds);

        return (int)Math.Clamp(seconds, 0, int.MaxValue);
    }

    private static TokenResponse CreateTokenResponse(string error, IdentityError identityError, int? lockoutSecondsRemaining = null)
    {
        return new TokenResponse
        {
            Error = error,
            Code = identityError.Code,
            ErrorDescription = identityError.Description,
            LockoutSecondsRemaining = lockoutSecondsRemaining,
        };
    }
}
