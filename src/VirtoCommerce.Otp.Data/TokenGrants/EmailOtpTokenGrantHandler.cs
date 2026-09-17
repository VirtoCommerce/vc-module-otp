using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Platform.Core;
using VirtoCommerce.Platform.Core.Common;
using VirtoCommerce.Platform.Core.Events;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Core.Security.Events;
using VirtoCommerce.Platform.Security.Exceptions;
using VirtoCommerce.Platform.Security.Extensions;
using VirtoCommerce.Platform.Security.OpenIddict;
using VirtoCommerce.Platform.Security.TokenGrants;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace VirtoCommerce.Otp.Data.TokenGrants;

/// <summary>
/// Handles the "email_otp_sign_in" token grant: verifies the emailed code via <see cref="IOtpService"/>
/// and signs in the matching user.
/// </summary>
public class EmailOtpTokenGrantHandler : ITokenGrantHandler
{
    private readonly IOtpService _otpService;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IdentityOptions _identityOptions;
    private readonly IEnumerable<ITokenRequestValidator> _requestValidators;
    private readonly IEnumerable<ITokenClaimProvider> _claimProviders;
    private readonly IEnumerable<ITokenRequestHandler> _requestHandlers;
    private readonly IEventPublisher _eventPublisher;

    public EmailOtpTokenGrantHandler(
        IOtpService otpService,
        SignInManager<ApplicationUser> signInManager,
        IOptions<IdentityOptions> identityOptions,
        IEnumerable<ITokenRequestValidator> requestValidators,
        IEnumerable<ITokenClaimProvider> claimProviders,
        IEnumerable<ITokenRequestHandler> requestHandlers,
        IEventPublisher eventPublisher)
    {
        _otpService = otpService;
        _signInManager = signInManager;
        _identityOptions = identityOptions.Value;
        _requestValidators = requestValidators;
        _claimProviders = claimProviders;
        _requestHandlers = requestHandlers;
        _eventPublisher = eventPublisher;
    }

    public string GrantType => PlatformConstants.Security.GrantTypes.EmailOtpSignIn;

    public async Task<TokenGrantResult> HandleAsync(OpenIddictRequest request, TokenRequestContext context)
    {
        var user = await ResolveUserAsync(request);
        if (user == null)
        {
            return TokenGrantResult.Failed(SecurityErrorDescriber.LoginFailed());
        }

        if (!await _signInManager.CanSignInAsync(user))
        {
            return TokenGrantResult.Failed(SecurityErrorDescriber.SignInNotAllowed());
        }

        context.User = user.CloneTyped();

        foreach (var requestValidator in _requestValidators)
        {
            var errors = await requestValidator.ValidateAsync(context);
            if (errors.Count > 0)
            {
                return TokenGrantResult.Failed(errors.First());
            }
        }

        await _eventPublisher.Publish(new BeforeUserLoginEvent(user));

        foreach (var requestHandler in _requestHandlers)
        {
            await requestHandler.HandleAsync(user, context);
        }

        var ticket = await CreateTicketAsync(user, context);
        ticket.Principal.SetAuthenticationMethod(GrantType, [Destinations.AccessToken]);

        user.LastLoginDate = DateTime.UtcNow;

        try
        {
            await _signInManager.UserManager.UpdateAsync(user);
        }
        catch (DuplicateEmailException)
        {
            return TokenGrantResult.Failed(SecurityErrorDescriber.DuplicateEmailLoginAttempt());
        }

        await _eventPublisher.Publish(new UserLoginEvent(user));

        return TokenGrantResult.SignedIn(ticket.Principal, ticket.Properties, context.AuthenticationScheme);
    }

    private async Task<ApplicationUser> ResolveUserAsync(OpenIddictRequest request)
    {
        var storeId = (string)request.GetParameter("storeId");
        var email = (string)request.GetParameter("email");
        var code = (string)request.GetParameter("code");

        if (string.IsNullOrEmpty(storeId) || string.IsNullOrEmpty(email) || string.IsNullOrEmpty(code))
        {
            return null;
        }

        var result = await _otpService.VerifyCodeAsync(storeId, email, code);

        return result.Outcome == OtpVerifyOutcome.Success ? result.User : null;
    }

    private async Task<AuthenticationTicket> CreateTicketAsync(ApplicationUser user, TokenRequestContext context)
    {
        var principal = await _signInManager.CreateUserPrincipalAsync(user);

        principal.SetScopes(new[]
        {
            Scopes.OpenId,
            Scopes.Email,
            Scopes.Profile,
            Scopes.OfflineAccess,
            Scopes.Roles
        }.Intersect(context.Request.GetScopes()));

        principal.SetResources("resource_server");

        foreach (var claim in principal.Claims)
        {
            if (claim.Type == _identityOptions.ClaimsIdentity.SecurityStampClaimType)
            {
                continue;
            }

            var destinations = new List<string>
            {
                Destinations.AccessToken
            };

            if (claim.Type == Claims.Name && principal.HasScope(Scopes.Profile) ||
                claim.Type == Claims.Email && principal.HasScope(Scopes.Email) ||
                claim.Type == Claims.Role && principal.HasScope(Scopes.Roles))
            {
                destinations.Add(Destinations.IdentityToken);
            }

            claim.SetDestinations(destinations);
        }

        foreach (var claimProvider in _claimProviders)
        {
            await claimProvider.SetClaimsAsync(principal, context);
        }

        return new AuthenticationTicket(principal, context.Properties, context.AuthenticationScheme);
    }
}
