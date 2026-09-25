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
    private const string _storeId = "store-1";

    [Fact]
    public void GrantType_Should_Be_OtpEmail()
    {
        // Arrange
        var context = CreateContext();

        // Act
        var grantType = context.Handler.GrantType;

        // Assert
        Assert.Equal(ModuleConstants.Security.GrantType, grantType);
    }

    [Fact]
    public async Task HandleAsync_Should_NameTheMissingParameters_When_RequiredParametersAreMissing()
    {
        // Arrange
        var context = CreateContext();
        var request = CreateRequest(email: _email, code: null, storeId: null);
        var requestContext = CreateRequestContext(request);

        // Act
        var actionResult = await context.Handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        var error = (TokenResponse)badRequest.Value;
        Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, error.Error);
        Assert.Equal("missing_parameter", error.Code);
        Assert.Equal("Missing required parameters: storeId, code.", error.ErrorDescription);
        Assert.Equal(ModuleConstants.Security.FailureReason.MissingParameter, requestContext.FailureReason);
        context.OtpService.Verify(x => x.VerifyCodeAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnInvalidCode_When_CodeVerificationFails()
    {
        // Arrange
        var context = CreateContext();

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.InvalidCode });

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request);

        // Act
        var actionResult = await context.Handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal("invalid_code", ((TokenResponse)badRequest.Value).Code);
        context.SignInManager.Verify(x => x.CanSignInAsync(It.IsAny<ApplicationUser>()), Times.Never);
        Assert.Equal(ModuleConstants.Security.FailureReason.InvalidCode, requestContext.FailureReason);
        Assert.False(requestContext.SignInResult.Succeeded);
    }

    [Fact]
    public async Task HandleAsync_Should_LogTheAttemptedEmail_When_NoUserWasResolved()
    {
        // Arrange
        var context = CreateContext();

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.UserNotFound });

        var request = CreateRequest(_email, _code);

        // Act
        await context.Handler.HandleAsync(CreateRequestContext(request));

        // Assert
        context.EventPublisher.Verify(x => x.Publish(It.Is<UserSignInAttemptEvent>(e =>
            e.Succeeded == false && e.UserName == _email && e.UserId == null)), Times.Once);
    }

    [Fact]
    public async Task HandleAsync_Should_LogTheResolvedUser_When_AccountIsLocked()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Id = "user-1", Email = _email };

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.AccountLocked, LockoutSecondsRemaining = 245, User = user });

        var request = CreateRequest(_email, _code);

        // Act
        await context.Handler.HandleAsync(CreateRequestContext(request));

        // Assert
        context.EventPublisher.Verify(x => x.Publish(It.Is<UserSignInAttemptEvent>(e =>
            e.Succeeded == false && e.UserId == "user-1")), Times.Once);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnAccountLocked_With_SecondsRemaining_When_UserIsLockedOut_And_DetailedErrorsEnabled()
    {
        // Arrange
        var context = CreateContext();

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.AccountLocked, LockoutSecondsRemaining = 245 });

        var request = CreateRequest(_email, _code);

        // Act
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request, detailedErrors: true));

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        var error = (TokenResponse)badRequest.Value;
        Assert.Equal("account_locked", error.Code);
        Assert.Equal(245, error.LockoutSecondsRemaining);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnInvalidCode_When_UserIsLockedOut_And_DetailedErrorsDisabled()
    {
        // Arrange
        var context = CreateContext();

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.AccountLocked, LockoutSecondsRemaining = 245 });

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request, detailedErrors: false);

        // Act
        var actionResult = await context.Handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        var error = (TokenResponse)badRequest.Value;
        Assert.Equal("invalid_code", error.Code);
        Assert.Null(error.LockoutSecondsRemaining);
        // The sign-in log gets the real reason even though the client only sees a generic error.
        Assert.Equal(SignInFailureReason.LockedOut, requestContext.FailureReason);
        Assert.True(requestContext.SignInResult.IsLockedOut);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task HandleAsync_Should_ReturnOtpDisabled_When_OtpIsDisabledForTheStore_Regardless_Of_DetailedErrors(bool detailedErrors)
    {
        // Arrange
        var context = CreateContext();

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.OtpDisabled });

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request, detailedErrors);

        // Act
        var actionResult = await context.Handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal("otp_disabled", ((TokenResponse)badRequest.Value).Code);
        Assert.Equal(ModuleConstants.Security.FailureReason.OtpDisabled, requestContext.FailureReason);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task HandleAsync_Should_ReturnStoreNotFound_When_StoreDoesNotExist_Regardless_Of_DetailedErrors(bool detailedErrors)
    {
        // Arrange
        var context = CreateContext();

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.StoreNotFound });

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request, detailedErrors);

        // Act
        var actionResult = await context.Handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        var error = (TokenResponse)badRequest.Value;
        Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, error.Error);
        Assert.Equal("store_not_found", error.Code);
        Assert.Equal(ModuleConstants.Security.FailureReason.StoreNotFound, requestContext.FailureReason);
    }

    [Theory]
    [InlineData(true, "duplicate_email_login_attempt")]
    [InlineData(false, "invalid_code")]
    public async Task HandleAsync_Should_HideDuplicateEmail_Unless_DetailedErrorsEnabled(bool detailedErrors, string expectedCode)
    {
        // Arrange
        var context = CreateContext();

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.DuplicateEmail });

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request, detailedErrors);

        // Act
        var actionResult = await context.Handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal(expectedCode, ((TokenResponse)badRequest.Value).Code);
        Assert.Equal(SignInFailureReason.DuplicateEmail, requestContext.FailureReason);
    }

    [Theory]
    [InlineData(true, "lockout_disabled")]
    [InlineData(false, "invalid_code")]
    public async Task HandleAsync_Should_HideLockoutDisabled_Unless_DetailedErrorsEnabled(bool detailedErrors, string expectedCode)
    {
        // Arrange
        var context = CreateContext();

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.LockoutDisabled });

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request, detailedErrors);

        // Act
        var actionResult = await context.Handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal(expectedCode, ((TokenResponse)badRequest.Value).Code);
        Assert.Equal(ModuleConstants.Security.FailureReason.LockoutDisabled, requestContext.FailureReason);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task HandleAsync_Should_ReturnUserCannotLoginInStore_When_StoreAccessIsDenied_Regardless_Of_DetailedErrors(bool detailedErrors)
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Id = "user-1", Email = _email };

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.StoreAccessDenied, User = user });

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request, detailedErrors);

        // Act
        var actionResult = await context.Handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal("user_cannot_login_in_store", ((TokenResponse)badRequest.Value).Code);
        Assert.Equal(SignInFailureReason.Forbidden, requestContext.FailureReason);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnUserNotFound_When_NoUserForEmail_And_DetailedErrorsEnabled()
    {
        // Arrange
        var context = CreateContext();

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.UserNotFound });

        var request = CreateRequest(_email, _code);

        // Act
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request, detailedErrors: true));

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal("user_not_found", ((TokenResponse)badRequest.Value).Code);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnInvalidCode_When_NoUserForEmail_And_DetailedErrorsDisabled()
    {
        // Arrange
        var context = CreateContext();

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.UserNotFound });

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request, detailedErrors: false);

        // Act
        var actionResult = await context.Handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal("invalid_code", ((TokenResponse)badRequest.Value).Code);
        Assert.Equal(SignInFailureReason.UserNotFound, requestContext.FailureReason);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnBadRequest_When_UserCannotSignIn()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email };

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.Success, User = user });

        context.SignInManager
            .Setup(x => x.CanSignInAsync(user))
            .ReturnsAsync(false);

        var request = CreateRequest(_email, _code);

        // Act
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request));

        // Assert
        Assert.IsType<BadRequestObjectResult>(actionResult);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnBadRequest_When_ARequestValidatorRejectsTheRequest()
    {
        // Arrange
        var validatorError = new TokenResponse { Code = "custom_error" };
        var validator = new Mock<ITokenRequestValidator>();

        validator
            .Setup(x => x.ValidateAsync(It.IsAny<TokenRequestContext>()))
            .ReturnsAsync([validatorError]);

        var context = CreateContext(requestValidators: [validator.Object]);
        var user = new ApplicationUser { Email = _email };

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.Success, User = user });

        context.SignInManager
            .Setup(x => x.CanSignInAsync(user))
            .ReturnsAsync(true);

        var request = CreateRequest(_email, _code);

        // Act
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request));

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Same(validatorError, badRequest.Value);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnBadRequest_When_UpdatingLastLoginDateHitsADuplicateEmail()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email };

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.Success, User = user });

        context.SignInManager
            .Setup(x => x.CanSignInAsync(user))
            .ReturnsAsync(true);

        context.SignInManager.Object.UserManager = context.UserManager.Object;

        context.SignInManager
            .Setup(x => x.CreateUserPrincipalAsync(user))
            .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity()));

        context.UserManager
            .Setup(x => x.UpdateAsync(user))
            .ThrowsAsync(new DuplicateEmailException("duplicate"));

        var request = CreateRequest(_email, _code);

        // Act
        var actionResult = await context.Handler.HandleAsync(CreateRequestContext(request));

        // Assert
        Assert.IsType<BadRequestObjectResult>(actionResult);
    }

    [Fact]
    public async Task HandleAsync_Should_SignIn_When_CodeIsValidAndUserCanSignIn()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email };

        context.OtpService
            .Setup(x => x.VerifyCodeAsync(_storeId, _email, _code))
            .ReturnsAsync(new OtpVerifyResult { Outcome = OtpVerifyOutcome.Success, User = user });

        context.SignInManager
            .Setup(x => x.CanSignInAsync(user))
            .ReturnsAsync(true);

        context.SignInManager.Object.UserManager = context.UserManager.Object;

        context.SignInManager
            .Setup(x => x.CreateUserPrincipalAsync(user))
            .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity()));

        var request = CreateRequest(_email, _code);
        var requestContext = CreateRequestContext(request);

        // Act
        var actionResult = await context.Handler.HandleAsync(requestContext);

        // Assert
        var signInResult = Assert.IsType<SignInResult>(actionResult);
        Assert.NotNull(signInResult.Principal);
        Assert.True(requestContext.SignInResult.Succeeded);
        context.UserManager.Verify(x => x.UpdateAsync(user), Times.Once);
        context.EventPublisher.Verify(x => x.Publish(It.IsAny<BeforeUserLoginEvent>()), Times.Once);
        context.EventPublisher.Verify(x => x.Publish(It.IsAny<UserLoginEvent>()), Times.Once);
    }

    private static OpenIddictRequest CreateRequest(string email, string code, string storeId = _storeId)
    {
        var request = new OpenIddictRequest { GrantType = ModuleConstants.Security.GrantType };
        request.SetParameter(ModuleConstants.Security.Parameters.Email, email);
        request.SetParameter(ModuleConstants.Security.Parameters.Code, code);
        request.SetParameter(ModuleConstants.Security.Parameters.StoreId, storeId);
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
            signInManager.Object,
            identityOptions,
            requestValidators ?? [],
            [],
            [],
            eventPublisher.Object,
            otpService.Object);

        return new TestContext(handler, otpService, signInManager, userManager, eventPublisher);
    }

    private sealed record TestContext(
        OtpGrantTypeHandler Handler,
        Mock<IOtpService> OtpService,
        Mock<SignInManager<ApplicationUser>> SignInManager,
        Mock<UserManager<ApplicationUser>> UserManager,
        Mock<IEventPublisher> EventPublisher);
}
