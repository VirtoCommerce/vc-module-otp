using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Moq;
using OpenIddict.Abstractions;
using VirtoCommerce.Otp.Core;
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
public class OtpGrantTypeHandlerTests : OtpTestsBase
{
    private readonly Mock<IEventPublisher> _eventPublisher;
    private readonly OtpGrantTypeHandler _handler;

    public OtpGrantTypeHandlerTests()
    {
        _eventPublisher = new Mock<IEventPublisher>();
        _handler = CreateHandler();
    }

    [Fact]
    public void GrantType_Should_Be_OtpEmail()
    {
        // Act
        var grantType = _handler.GrantType;

        // Assert
        Assert.Equal(ModuleConstants.Security.GrantType, grantType);
    }

    [Fact]
    public async Task HandleAsync_Should_NameTheMissingParameters_When_RequiredParametersAreMissing()
    {
        // Arrange
        var requestContext = CreateRequestContext(email: ActiveUserEmail, code: null, storeId: null);

        // Act
        var actionResult = await _handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        var error = (TokenResponse)badRequest.Value;
        Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, error.Error);
        Assert.Equal("missing_parameter", error.Code);
        Assert.Equal("Missing required parameters: storeId, code.", error.ErrorDescription);
        Assert.Equal(ModuleConstants.Security.FailureReason.MissingParameter, requestContext.FailureReason);
        StoreService.Verify(x => x.GetAsync(It.IsAny<IList<string>>(), It.IsAny<string>(), It.IsAny<bool>()), Times.Never);
    }

    [Theory]
    [InlineData(StoreId, ActiveUserEmail, InvalidCode, true, "invalid_code", ModuleConstants.Security.FailureReason.InvalidCode)]
    [InlineData(StoreId, ActiveUserEmail, InvalidCode, false, "invalid_code", ModuleConstants.Security.FailureReason.InvalidCode)]
    [InlineData(UnknownStoreId, ActiveUserEmail, ValidCode, true, "store_not_found", ModuleConstants.Security.FailureReason.StoreNotFound)]
    [InlineData(UnknownStoreId, ActiveUserEmail, ValidCode, false, "store_not_found", ModuleConstants.Security.FailureReason.StoreNotFound)]
    [InlineData(OtpDisabledStoreId, ActiveUserEmail, ValidCode, true, "otp_disabled", ModuleConstants.Security.FailureReason.OtpDisabled)]
    [InlineData(OtpDisabledStoreId, ActiveUserEmail, ValidCode, false, "otp_disabled", ModuleConstants.Security.FailureReason.OtpDisabled)]
    [InlineData(StoreId, UnknownEmail, ValidCode, true, "user_not_found", SignInFailureReason.UserNotFound)]
    [InlineData(StoreId, UnknownEmail, ValidCode, false, "invalid_code", SignInFailureReason.UserNotFound)]
    [InlineData(StoreId, DuplicateEmail, ValidCode, true, "duplicate_email_login_attempt", SignInFailureReason.DuplicateEmail)]
    [InlineData(StoreId, DuplicateEmail, ValidCode, false, "invalid_code", SignInFailureReason.DuplicateEmail)]
    [InlineData(StoreId, LockoutDisabledUserEmail, ValidCode, true, "lockout_disabled", ModuleConstants.Security.FailureReason.LockoutDisabled)]
    [InlineData(StoreId, LockoutDisabledUserEmail, ValidCode, false, "invalid_code", ModuleConstants.Security.FailureReason.LockoutDisabled)]
    [InlineData(StoreId, TemporarilyLockedUserEmail, ValidCode, true, "user_is_temporary_locked_out", SignInFailureReason.LockedOut)]
    [InlineData(StoreId, TemporarilyLockedUserEmail, ValidCode, false, "invalid_code", SignInFailureReason.LockedOut)]
    [InlineData(StoreId, PermanentlyLockedUserEmail, ValidCode, true, "user_is_locked_out", SignInFailureReason.LockedOut)]
    [InlineData(StoreId, PermanentlyLockedUserEmail, ValidCode, false, "invalid_code", SignInFailureReason.LockedOut)]
    [InlineData(StoreId, UntrustedStoreUserEmail, ValidCode, true, "user_cannot_login_in_store", SignInFailureReason.Forbidden)]
    [InlineData(StoreId, UntrustedStoreUserEmail, ValidCode, false, "user_cannot_login_in_store", SignInFailureReason.Forbidden)]
    [InlineData(StoreId, UnconfirmedEmailUserEmail, ValidCode, true, "sign_in_not_allowed", SignInFailureReason.NotAllowed)]
    [InlineData(StoreId, UnconfirmedEmailUserEmail, ValidCode, false, "sign_in_not_allowed", SignInFailureReason.NotAllowed)]
    public async Task HandleAsync_Should_ReturnExpectedError(string storeId, string email, string code, bool detailedErrors, string expectedErrorCode, string expectedFailureReason)
    {
        // Arrange
        var requestContext = CreateRequestContext(email, code, storeId, detailedErrors);

        // Act
        var actionResult = await _handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal(expectedErrorCode, ((TokenResponse)badRequest.Value).Code);
        Assert.Equal(expectedFailureReason, requestContext.FailureReason);
    }

    [Fact]
    public async Task HandleAsync_Should_NotCheckWhetherTheUserCanSignIn_When_CodeIsInvalid()
    {
        // Arrange
        var requestContext = CreateRequestContext(ActiveUserEmail, InvalidCode);

        // Act
        await _handler.HandleAsync(requestContext);

        // Assert
        Assert.False(requestContext.SignInResult.Succeeded);
        SignInManager.Verify(x => x.CanSignInAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_Should_ReportAnInvalidRequest_When_StoreDoesNotExist()
    {
        // Arrange
        var requestContext = CreateRequestContext(ActiveUserEmail, ValidCode, UnknownStoreId);

        // Act
        var actionResult = await _handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, ((TokenResponse)badRequest.Value).Error);
    }

    [Theory]
    [InlineData(TemporarilyLockedUserEmail, true, LockoutSeconds)]
    [InlineData(TemporarilyLockedUserEmail, false, null)]
    [InlineData(PermanentlyLockedUserEmail, true, int.MaxValue)]
    [InlineData(PermanentlyLockedUserEmail, false, null)]
    public async Task HandleAsync_Should_ReportLockoutSeconds_Only_When_DetailedErrorsEnabled(string email, bool detailedErrors, int? expectedSecondsRemaining)
    {
        // Arrange
        var requestContext = CreateRequestContext(email, ValidCode, detailedErrors: detailedErrors);

        // Act
        var actionResult = await _handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Equal(expectedSecondsRemaining, ((TokenResponse)badRequest.Value).LockoutSecondsRemaining);
        Assert.True(requestContext.SignInResult.IsLockedOut);
    }

    [Theory]
    [InlineData(ActiveUserEmail, InvalidCode, ActiveUserId)]
    [InlineData(TemporarilyLockedUserEmail, ValidCode, TemporarilyLockedUserId)]
    [InlineData(PermanentlyLockedUserEmail, ValidCode, PermanentlyLockedUserId)]
    [InlineData(UnknownEmail, ValidCode, null)]
    public async Task HandleAsync_Should_LogTheFailedSignInAttempt(string email, string code, string expectedUserId)
    {
        // Arrange
        var requestContext = CreateRequestContext(email, code);

        // Act
        await _handler.HandleAsync(requestContext);

        // Assert
        _eventPublisher.Verify(x => x.Publish(It.Is<UserSignInAttemptEvent>(e =>
            e.Succeeded == false && e.UserName == email && e.UserId == expectedUserId)), Times.Once);
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

        var handler = CreateHandler([validator.Object]);
        var requestContext = CreateRequestContext(ActiveUserEmail, ValidCode);

        // Act
        var actionResult = await handler.HandleAsync(requestContext);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(actionResult);
        Assert.Same(validatorError, badRequest.Value);
    }

    [Fact]
    public async Task HandleAsync_Should_ReturnBadRequest_When_UpdatingLastLoginDateHitsADuplicateEmail()
    {
        // Arrange
        UserManager
            .Setup(x => x.UpdateAsync(ActiveUser))
            .ThrowsAsync(new DuplicateEmailException("duplicate"));

        var requestContext = CreateRequestContext(ActiveUserEmail, ValidCode);

        // Act
        var actionResult = await _handler.HandleAsync(requestContext);

        // Assert
        Assert.IsType<BadRequestObjectResult>(actionResult);
    }

    [Fact]
    public async Task HandleAsync_Should_SignIn_When_CodeIsValidAndUserCanSignIn()
    {
        // Arrange
        var requestContext = CreateRequestContext(ActiveUserEmail, ValidCode);

        // Act
        var actionResult = await _handler.HandleAsync(requestContext);

        // Assert
        var signInResult = Assert.IsType<SignInResult>(actionResult);
        Assert.NotNull(signInResult.Principal);
        Assert.True(requestContext.SignInResult.Succeeded);
        UserManager.Verify(x => x.UpdateAsync(ActiveUser), Times.Once);
        _eventPublisher.Verify(x => x.Publish(It.IsAny<BeforeUserLoginEvent>()), Times.Once);
        _eventPublisher.Verify(x => x.Publish(It.IsAny<UserLoginEvent>()), Times.Once);
    }

    private static TokenRequestContext CreateRequestContext(string email, string code, string storeId = StoreId, bool detailedErrors = false)
    {
        var request = new OpenIddictRequest { GrantType = ModuleConstants.Security.GrantType };
        request.SetParameter(ModuleConstants.Security.Parameters.Email, email);
        request.SetParameter(ModuleConstants.Security.Parameters.Code, code);
        request.SetParameter(ModuleConstants.Security.Parameters.StoreId, storeId);

        return new TokenRequestContext
        {
            AuthenticationScheme = "test-scheme",
            Request = request,
            Properties = new AuthenticationProperties(),
            DetailedErrors = detailedErrors,
        };
    }

    private OtpGrantTypeHandler CreateHandler(IEnumerable<ITokenRequestValidator> requestValidators = null)
    {
        return new OtpGrantTypeHandler(
            SignInManager.Object,
            IdentityOptions,
            requestValidators ?? [],
            [],
            [],
            _eventPublisher.Object,
            OtpService);
    }
}
