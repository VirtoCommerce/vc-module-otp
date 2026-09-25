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
    [InlineData(OtpRequestOutcome.CodeSent, false, OtpRequestOutcome.CodeSent)]
    [InlineData(OtpRequestOutcome.OtpDisabled, true, OtpRequestOutcome.OtpDisabled)]
    [InlineData(OtpRequestOutcome.OtpDisabled, false, OtpRequestOutcome.OtpDisabled)]
    [InlineData(OtpRequestOutcome.UserNotFound, true, OtpRequestOutcome.UserNotFound)]
    [InlineData(OtpRequestOutcome.UserNotFound, false, OtpRequestOutcome.CodeSent)]
    [InlineData(OtpRequestOutcome.DuplicateEmail, true, OtpRequestOutcome.DuplicateEmail)]
    [InlineData(OtpRequestOutcome.DuplicateEmail, false, OtpRequestOutcome.CodeSent)]
    [InlineData(OtpRequestOutcome.LockoutDisabled, true, OtpRequestOutcome.LockoutDisabled)]
    [InlineData(OtpRequestOutcome.LockoutDisabled, false, OtpRequestOutcome.CodeSent)]
    [InlineData(OtpRequestOutcome.StoreAccessDenied, true, OtpRequestOutcome.StoreAccessDenied)]
    [InlineData(OtpRequestOutcome.StoreAccessDenied, false, OtpRequestOutcome.CodeSent)]
    public async Task RequestCode_Should_ReturnExpectedOutcome(OtpRequestOutcome serviceOutcome, bool detailedErrors, OtpRequestOutcome expectedOutcome)
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
        Assert.Equal(expectedOutcome, result.Outcome);
        Assert.Equal("b•••r@acme.com", result.MaskedEmail);
    }

    private static OtpController CreateController(bool detailedErrors, out Mock<IOtpService> otpService)
    {
        otpService = new Mock<IOtpService>();
        var passwordLoginOptions = Options.Create(new PasswordLoginOptions { DetailedErrors = detailedErrors });

        return new OtpController(otpService.Object, passwordLoginOptions);
    }
}
