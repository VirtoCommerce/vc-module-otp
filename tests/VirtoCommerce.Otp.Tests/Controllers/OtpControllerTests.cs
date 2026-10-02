using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Web.Controllers.Api;
using VirtoCommerce.Platform.Core.Security;
using Xunit;

namespace VirtoCommerce.Otp.Tests.Controllers;

[Trait("Category", "Unit")]
public class OtpControllerTests : OtpTestsBase
{
    [Theory]
    [InlineData(StoreId, ActiveUserEmail, false, null)]
    [InlineData(UnknownStoreId, ActiveUserEmail, true, "store_not_found")]
    [InlineData(UnknownStoreId, ActiveUserEmail, false, "store_not_found")]
    [InlineData(OtpDisabledStoreId, ActiveUserEmail, true, "otp_disabled")]
    [InlineData(OtpDisabledStoreId, ActiveUserEmail, false, "otp_disabled")]
    [InlineData(StoreId, UnknownEmail, true, "user_not_found")]
    [InlineData(StoreId, UnknownEmail, false, null)]
    [InlineData(StoreId, DuplicateEmail, true, "duplicate_email_login_attempt")]
    [InlineData(StoreId, DuplicateEmail, false, null)]
    [InlineData(StoreId, LockoutDisabledUserEmail, true, "lockout_disabled")]
    [InlineData(StoreId, LockoutDisabledUserEmail, false, null)]
    [InlineData(StoreId, TemporarilyLockedUserEmail, true, "user_is_temporary_locked_out")]
    [InlineData(StoreId, TemporarilyLockedUserEmail, false, null)]
    [InlineData(StoreId, PermanentlyLockedUserEmail, true, "user_is_locked_out")]
    [InlineData(StoreId, PermanentlyLockedUserEmail, false, null)]
    [InlineData(StoreId, UntrustedStoreUserEmail, true, "user_cannot_login_in_store")]
    [InlineData(StoreId, UntrustedStoreUserEmail, false, null)]
    public async Task RequestCode_Should_ReturnExpectedResult(string storeId, string email, bool detailedErrors, string expectedErrorCode)
    {
        // Arrange
        var controller = CreateController(detailedErrors);

        // Act
        var actionResult = await controller.RequestCode(new OtpRequest { Email = email, StoreId = storeId });

        // Assert
        var result = Assert.IsType<OtpRequestResult>(Assert.IsType<OkObjectResult>(actionResult.Result).Value);
        Assert.Equal(expectedErrorCode is null, result.Succeeded);
        Assert.Equal(expectedErrorCode, result.Error?.Code);
    }

    [Theory]
    [InlineData(TemporarilyLockedUserEmail, true, LockoutSeconds)]
    [InlineData(TemporarilyLockedUserEmail, false, null)]
    [InlineData(PermanentlyLockedUserEmail, true, int.MaxValue)]
    [InlineData(PermanentlyLockedUserEmail, false, null)]
    public async Task RequestCode_Should_ReportLockoutSeconds_Like_TheTokenEndpoint(string email, bool detailedErrors, int? expectedSecondsRemaining)
    {
        // Arrange
        var controller = CreateController(detailedErrors);

        // Act
        var actionResult = await controller.RequestCode(new OtpRequest { Email = email, StoreId = StoreId });

        // Assert
        var result = Assert.IsType<OtpRequestResult>(Assert.IsType<OkObjectResult>(actionResult.Result).Value);
        Assert.Equal(expectedSecondsRemaining, result.LockoutSecondsRemaining);
    }

    [Fact]
    public async Task RequestCode_Should_ReturnTheMaskedEmail()
    {
        // Arrange
        var controller = CreateController(detailedErrors: false);

        // Act
        var actionResult = await controller.RequestCode(new OtpRequest { Email = ActiveUserEmail, StoreId = StoreId });

        // Assert
        var result = Assert.IsType<OtpRequestResult>(Assert.IsType<OkObjectResult>(actionResult.Result).Value);
        Assert.Equal("a•••e@acme.com", result.MaskedEmail);
    }

    private OtpController CreateController(bool detailedErrors)
    {
        var passwordLoginOptions = Options.Create(new PasswordLoginOptions { DetailedErrors = detailedErrors });

        return new OtpController(OtpService, passwordLoginOptions);
    }
}
