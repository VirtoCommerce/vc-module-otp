using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Otp.Data.Services;
using VirtoCommerce.Platform.Core.Events;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Core.Security.Events;
using VirtoCommerce.Platform.Core.Security.SignInLog;
using VirtoCommerce.Platform.Security.Exceptions;
using VirtoCommerce.Platform.Security.OpenIddict;
using Xunit;
using SignInResult = Microsoft.AspNetCore.Mvc.SignInResult;

namespace VirtoCommerce.Otp.Tests.Services;

[Trait("Category", "Unit")]
public class OtpGrantTypeHandlerTests
{
    private const string _email = "buyer@acme.com";
    private const string _code = "123456";

    [Fact]
    public void GrantType_Should_Be_OtpEmail()
    {
        var context = CreateContext();

        Assert.Equal(ModuleConstants.Security.GrantType, context.Handler.GrantType);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnBadRequest_When_RequiredParametersAreMissing()
    {
        var context = CreateContext();
        var request = CreateRequest(email: _email, code: null);

        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request));

        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal("invalid_code", ((TokenResponse)badRequest.Value).Code);
        context.OtpService.Verify(x => x.VerifyCodeAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnInvalidCode_When_CodeVerificationFails()
    {
        var context = CreateContext();
        context.OtpService.Setup(x => x.VerifyCodeAsync(_email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.InvalidCode });

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request);
        var actionResult = await context.Handler.HandleAsync(requestContext);

        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal("invalid_code", ((TokenResponse)badRequest.Value).Code);
        context.SignInManager.Verify(x => x.CanSignInAsync(It.IsAny<ApplicationUser>()), Times.Never);
        Assert.Equal(ModuleConstants.Security.FailureReason.InvalidCode, requestContext.FailureReason);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnAccountLocked_With_SecondsRemaining_When_UserIsLockedOut_And_DetailedErrorsEnabled()
    {
        var context = CreateContext();
        context.OtpService.Setup(x => x.VerifyCodeAsync(_email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.AccountLocked, LockoutSecondsRemaining = 245 });

        var request = CreateRequest(_email, _code);
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request, detailedErrors: true));

        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        var error = (TokenResponse)badRequest.Value;
        Assert.Equal("account_locked", error.Code);
        Assert.Equal(245, error.LockoutSecondsRemaining);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnInvalidCode_When_UserIsLockedOut_And_DetailedErrorsDisabled()
    {
        var context = CreateContext();
        context.OtpService.Setup(x => x.VerifyCodeAsync(_email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.AccountLocked, LockoutSecondsRemaining = 245 });

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request, detailedErrors: false);
        var actionResult = await context.Handler.HandleAsync(requestContext);

        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        var error = (TokenResponse)badRequest.Value;
        Assert.Equal("invalid_code", error.Code);
        Assert.Null(error.LockoutSecondsRemaining);
        // The sign-in log gets the real reason even though the client only sees a generic error.
        Assert.Equal(SignInFailureReason.LockedOut, requestContext.FailureReason);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnOtpDisabled_When_OtpIsDisabledForTheStore_And_DetailedErrorsEnabled()
    {
        var context = CreateContext();
        context.OtpService.Setup(x => x.VerifyCodeAsync(_email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.OtpDisabled });

        var request = CreateRequest(_email, _code);
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request, detailedErrors: true));

        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal("otp_disabled", ((TokenResponse)badRequest.Value).Code);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnInvalidCode_When_OtpIsDisabledForTheStore_And_DetailedErrorsDisabled()
    {
        var context = CreateContext();
        context.OtpService.Setup(x => x.VerifyCodeAsync(_email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.OtpDisabled });

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request, detailedErrors: false);
        var actionResult = await context.Handler.HandleAsync(requestContext);

        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal("invalid_code", ((TokenResponse)badRequest.Value).Code);
        // The sign-in log gets the real reason even though the client only sees a generic error.
        Assert.Equal(ModuleConstants.Security.FailureReason.OtpDisabled, requestContext.FailureReason);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnBadRequest_When_UserCannotSignIn()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email };
        context.OtpService.Setup(x => x.VerifyCodeAsync(_email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.Success, User = user });
        context.SignInManager.Setup(x => x.CanSignInAsync(user)).ReturnsAsync(false);

        var request = CreateRequest(_email, _code);
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request));

        Assert.IsType<BadRequestObjectResult>(actionResult);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnBadRequest_When_ARequestValidatorRejectsTheRequest()
    {
        var validatorError = new TokenResponse { Code = "custom_error" };
        var validator = new Mock<ITokenRequestValidator>();
        validator.Setup(x => x.ValidateAsync(It.IsAny<TokenRequestContext>()))
            .ReturnsAsync([validatorError]);

        var context = CreateContext(requestValidators: [validator.Object]);
        var user = new ApplicationUser { Email = _email };
        context.OtpService.Setup(x => x.VerifyCodeAsync(_email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.Success, User = user });
        context.SignInManager.Setup(x => x.CanSignInAsync(user)).ReturnsAsync(true);

        var request = CreateRequest(_email, _code);
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request));

        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Same(validatorError, badRequest.Value);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnBadRequest_When_UpdatingLastLoginDateHitsADuplicateEmail()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email };
        context.OtpService.Setup(x => x.VerifyCodeAsync(_email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.Success, User = user });
        context.SignInManager.Setup(x => x.CanSignInAsync(user)).ReturnsAsync(true);
        context.SignInManager.Object.UserManager = context.UserManager.Object;
        context.SignInManager.Setup(x => x.CreateUserPrincipalAsync(user)).ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity()));
        context.UserManager.Setup(x => x.UpdateAsync(user)).ThrowsAsync(new DuplicateEmailException("duplicate"));

        var request = CreateRequest(_email, _code);
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request));

        Assert.IsType<BadRequestObjectResult>(actionResult);
    }

    [Fact]
    public async Task HandleAsync_Should_SignIn_When_CodeIsValidAndUserCanSignIn()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email };
        context.OtpService.Setup(x => x.VerifyCodeAsync(_email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.Success, User = user });
        context.SignInManager.Setup(x => x.CanSignInAsync(user)).ReturnsAsync(true);
        context.SignInManager.Object.UserManager = context.UserManager.Object;
        context.SignInManager.Setup(x => x.CreateUserPrincipalAsync(user)).ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity()));

        var request = CreateRequest(_email, _code);
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request));

        var signInResult = Assert.IsType<SignInResult>(actionResult);
        Assert.NotNull(signInResult.Principal);
        context.UserManager.Verify(x => x.UpdateAsync(user), Times.Once);
        context.EventPublisher.Verify(x => x.Publish(It.IsAny<BeforeUserLoginEvent>()), Times.Once);
        context.EventPublisher.Verify(x => x.Publish(It.IsAny<UserLoginEvent>()), Times.Once);
    }

    [Fact]
    public async Task HandleAsync_Should_ForwardStoreId_When_Provided()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email };
        context.OtpService.Setup(x => x.VerifyCodeAsync(_email, _code, "store-1"))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.Success, User = user });
        context.SignInManager.Setup(x => x.CanSignInAsync(user)).ReturnsAsync(true);
        context.SignInManager.Object.UserManager = context.UserManager.Object;
        context.SignInManager.Setup(x => x.CreateUserPrincipalAsync(user)).ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity()));

        var request = CreateRequest(_email, _code, storeId: "store-1");
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request));

        Assert.IsType<SignInResult>(actionResult);
    }

    private static OpenIddictRequest CreateRequest(string email, string code, string storeId = null)
    {
        var request = new OpenIddictRequest { GrantType = ModuleConstants.Security.GrantType };
        request.SetParameter("email", email);
        request.SetParameter("code", code);
        request.SetParameter("storeId", storeId);
        return request;
    }

    private static TokenRequestContext CreateRequestContext(OpenIddictRequest request, bool detailedErrors = false)
    {
        return new TokenRequestContext
        {
            AuthenticationScheme = "test-scheme",
            Request = request,
            Properties = new AuthenticationProperties(),
            DetailedErrors = detailedErrors,
        };
    }

    private static TestContext CreateContext(IEnumerable<ITokenRequestValidator> requestValidators = null)
    {
        var otpService = new Mock<IOtpService>();

        var userStore = new Mock<IUserStore<ApplicationUser>>();
        var userManager = new Mock<UserManager<ApplicationUser>>(userStore.Object, null, null, null, null, null, null, null, null);

        var contextAccessor = new Mock<IHttpContextAccessor>();
        var claimsFactory = new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>();
        var identityOptions = Options.Create(new IdentityOptions());
        var logger = new Mock<ILogger<SignInManager<ApplicationUser>>>();
        var schemes = new Mock<IAuthenticationSchemeProvider>();
        var confirmation = new Mock<IUserConfirmation<ApplicationUser>>();

        var signInManager = new Mock<SignInManager<ApplicationUser>>(
            userManager.Object, contextAccessor.Object, claimsFactory.Object, identityOptions, logger.Object, schemes.Object, confirmation.Object);

        var eventPublisher = new Mock<IEventPublisher>();

        var handler = new OtpGrantTypeHandler(
            otpService.Object,
            signInManager.Object,
            identityOptions,
            requestValidators ?? [],
            [],
            [],
            eventPublisher.Object);

        return new TestContext(handler, otpService, signInManager, userManager, eventPublisher);
    }

    private sealed record TestContext(
        OtpGrantTypeHandler Handler,
        Mock<IOtpService> OtpService,
        Mock<SignInManager<ApplicationUser>> SignInManager,
        Mock<UserManager<ApplicationUser>> UserManager,
        Mock<IEventPublisher> EventPublisher);
}
