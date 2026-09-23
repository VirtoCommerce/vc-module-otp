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

    [Fact]
    public async Task RequestCode_Should_ReturnDisabled_When_DetailedErrorsEnabled()
    {
        var controller = CreateController(detailedErrors: true, out var otpService);
        otpService.Setup(x => x.RequestCodeAsync(_email))
            .ReturnsAsync(new OtpRequestResult { Outcome = OtpRequestOutcome.OtpDisabled, MaskedEmail = "b•••r@acme.com" });

        var actionResult = await controller.RequestCode(new OtpRequest { Email = _email });

        var result = Assert.IsType<OtpRequestResult>(Assert.IsType<OkObjectResult>(actionResult.Result).Value);
        Assert.Equal(OtpRequestOutcome.OtpDisabled, result.Outcome);
    }

    [Fact]
    public async Task RequestCode_Should_ReturnSent_When_DetailedErrorsDisabled()
    {
        var controller = CreateController(detailedErrors: false, out var otpService);
        otpService.Setup(x => x.RequestCodeAsync(_email))
            .ReturnsAsync(new OtpRequestResult { Outcome = OtpRequestOutcome.OtpDisabled, MaskedEmail = "b•••r@acme.com" });

        var actionResult = await controller.RequestCode(new OtpRequest { Email = _email });

        var result = Assert.IsType<OtpRequestResult>(Assert.IsType<OkObjectResult>(actionResult.Result).Value);
        Assert.Equal(OtpRequestOutcome.CodeSent, result.Outcome);
    }

    [Fact]
    public async Task RequestCode_Should_ReturnSent_Unchanged_When_CodeWasActuallySent()
    {
        var controller = CreateController(detailedErrors: false, out var otpService);
        otpService.Setup(x => x.RequestCodeAsync(_email))
            .ReturnsAsync(new OtpRequestResult { Outcome = OtpRequestOutcome.CodeSent, MaskedEmail = "b•••r@acme.com" });

        var actionResult = await controller.RequestCode(new OtpRequest { Email = _email });

        var result = Assert.IsType<OtpRequestResult>(Assert.IsType<OkObjectResult>(actionResult.Result).Value);
        Assert.Equal(OtpRequestOutcome.CodeSent, result.Outcome);
    }

    private static OtpController CreateController(bool detailedErrors, out Mock<IOtpService> otpService)
    {
        otpService = new Mock<IOtpService>();
        var passwordLoginOptions = Options.Create(new PasswordLoginOptions { DetailedErrors = detailedErrors });

        return new OtpController(otpService.Object, passwordLoginOptions);
    }
}
