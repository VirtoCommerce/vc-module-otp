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

    protected override string SignInType => "OTP";

    protected override async Task<GrantValidationResult> ValidateGrantAsync(TokenRequestContext context)
    {
        var missingParameters = new List<string>();

        var storeId = GetRequiredParameter(context.Request, ModuleConstants.Security.Parameters.StoreId, missingParameters);
        var email = GetRequiredParameter(context.Request, ModuleConstants.Security.Parameters.Email, missingParameters);
        var code = GetRequiredParameter(context.Request, ModuleConstants.Security.Parameters.Code, missingParameters);

        if (missingParameters.Count > 0)
        {
            context.FailureReason = ModuleConstants.Security.FailureReason.MissingParameter;

            return GrantValidationResult.Fail(new TokenResponse
            {
                Error = Errors.InvalidRequest,
                Code = "missing_parameter",
                ErrorDescription = $"Missing required parameters: {string.Join(", ", missingParameters)}.",
            });
        }

        var verifyResult = await otpService.VerifyCodeAsync(storeId, email, code);
        context.SignInResult = GetSignInResult(verifyResult.Outcome);

        if (verifyResult.Outcome != OtpVerifyOutcome.Success)
        {
            context.FailureReason = GetFailureReason(verifyResult.Outcome);

            return new GrantValidationResult
            {
                Error = BuildErrorResponse(verifyResult, context.DetailedErrors),
                User = verifyResult.User,
            };
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

    private static string GetFailureReason(OtpVerifyOutcome outcome)
    {
        return outcome switch
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
    }

    private static TokenResponse BuildErrorResponse(OtpVerifyResult verifyResult, bool detailedErrors)
    {
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
            OtpVerifyOutcome.UserNotFound when detailedErrors => new TokenResponse
            {
                Error = Errors.InvalidGrant,
                Code = "user_not_found",
                ErrorDescription = "No user with this email was found.",
            },
            OtpVerifyOutcome.DuplicateEmail when detailedErrors => SecurityErrorDescriber.DuplicateEmailLoginAttempt(),
            OtpVerifyOutcome.LockoutDisabled when detailedErrors => new TokenResponse
            {
                Error = Errors.InvalidGrant,
                Code = "lockout_disabled",
                ErrorDescription = "OTP sign-in is not available for accounts without lockout protection.",
            },
            OtpVerifyOutcome.AccountLocked when detailedErrors => new TokenResponse
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
