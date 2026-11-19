using System.Threading.Tasks;
using Moq;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Data.Services;
using VirtoCommerce.Platform.Core.Settings;
using Xunit;
using OtpModuleSettings = VirtoCommerce.Otp.Core.ModuleConstants.Settings.General;

namespace VirtoCommerce.Otp.Tests.Services;

[Trait("Category", "Unit")]
public class OtpSignInMethodProviderTests
{
    [Fact]
    public async Task GetSignInMethodsAsync_OtpSignInEnabled_ReturnsOtpMethod()
    {
        // Arrange
        var provider = CreateProvider(isOtpSignInEnabled: true);

        // Act
        var signInMethods = await provider.GetSignInMethodsAsync();

        // Assert
        var signInMethod = Assert.Single(signInMethods);
        Assert.Equal(ModuleConstants.Security.SignInType, signInMethod.Name);
        Assert.Equal(ModuleConstants.Security.SignInType, signInMethod.DisplayName);
    }

    [Fact]
    public async Task GetSignInMethodsAsync_OtpSignInDisabled_ReturnsNothing()
    {
        // Arrange
        var provider = CreateProvider(isOtpSignInEnabled: false);

        // Act
        var signInMethods = await provider.GetSignInMethodsAsync();

        // Assert
        Assert.Empty(signInMethods);
    }

    private static OtpSignInMethodProvider CreateProvider(bool isOtpSignInEnabled)
    {
        var settingsManager = new Mock<ISettingsManager>();

        settingsManager
            .Setup(x => x.GetObjectSettingAsync(OtpModuleSettings.OtpSignInEnabled.Name, null, null))
            .ReturnsAsync(new ObjectSettingEntry { Value = isOtpSignInEnabled });

        return new OtpSignInMethodProvider(settingsManager.Object);
    }
}
