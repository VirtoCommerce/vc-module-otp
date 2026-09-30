using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Otp.Web.Controllers.Api;
using VirtoCommerce.Platform.Core.Security;
using Xunit;

namespace VirtoCommerce.Otp.Tests.Controllers;

[Trait("Category", "Unit")]
public class OtpControllerTests
{
    private const string _email = "buyer@acme.com";
    private const string _storeId = "store-1";

    [Theory]
    [InlineData(OtpRequestOutcome.CodeSent, false, null)]
    [InlineData(OtpRequestOutcome.StoreNotFound, true, "store_not_found")]
    [InlineData(OtpRequestOutcome.StoreNotFound, false, "store_not_found")]
    [InlineData(OtpRequestOutcome.OtpDisabled, true, "otp_disabled")]
    [InlineData(OtpRequestOutcome.OtpDisabled, false, "otp_disabled")]
    [InlineData(OtpRequestOutcome.UserNotFound, true, "user_not_found")]
    [InlineData(OtpRequestOutcome.UserNotFound, false, null)]
    [InlineData(OtpRequestOutcome.DuplicateEmail, true, "duplicate_email_login_attempt")]
    [InlineData(OtpRequestOutcome.DuplicateEmail, false, null)]
    [InlineData(OtpRequestOutcome.LockoutDisabled, true, "lockout_disabled")]
    [InlineData(OtpRequestOutcome.LockoutDisabled, false, null)]
    [InlineData(OtpRequestOutcome.StoreAccessDenied, true, "user_cannot_login_in_store")]
    [InlineData(OtpRequestOutcome.StoreAccessDenied, false, null)]
    public async Task RequestCode_Should_ReturnExpectedResult(OtpRequestOutcome serviceOutcome, bool detailedErrors, string expectedErrorCode)
    {
        // Arrange
        var controller = CreateController(detailedErrors, out var otpService);

        otpService
            .Setup(x => x.RequestCodeAsync(_storeId, _email))
            .ReturnsAsync(serviceOutcome);

        // Act
        var actionResult = await controller.RequestCode(new OtpRequest { Email = _email, StoreId = _storeId });

        // Assert
        var result = Assert.IsType<OtpRequestResult>(Assert.IsType<OkObjectResult>(actionResult.Result).Value);
        Assert.Equal(expectedErrorCode is null, result.Succeeded);
        Assert.Equal(expectedErrorCode, result.Error?.Code);
        Assert.Equal("b•••r@acme.com", result.MaskedEmail);
    }

    private static OtpController CreateController(bool detailedErrors, out Mock<IOtpService> otpService)
    {
        otpService = new Mock<IOtpService>();
        var passwordLoginOptions = Options.Create(new PasswordLoginOptions { DetailedErrors = detailedErrors });

        return new OtpController(otpService.Object, passwordLoginOptions);
    }
}
