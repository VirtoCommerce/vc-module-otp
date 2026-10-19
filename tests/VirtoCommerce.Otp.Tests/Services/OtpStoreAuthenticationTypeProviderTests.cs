using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Moq;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Data.Services;
using VirtoCommerce.Platform.Core.Settings;
using VirtoCommerce.StoreModule.Core.Model;
using VirtoCommerce.StoreModule.Core.Services;
using Xunit;
using OtpModuleSettings = VirtoCommerce.Otp.Core.ModuleConstants.Settings.General;

namespace VirtoCommerce.Otp.Tests.Services;

[Trait("Category", "Unit")]
public class OtpStoreAuthenticationTypeProviderTests
{
    private const string StoreId = "test-store";
    private const string UnknownStoreId = "unknown-store";

    private readonly Mock<IStoreService> _storeService = new();
    private readonly Store _store = new() { Id = StoreId, Settings = [] };

    public OtpStoreAuthenticationTypeProviderTests()
    {
        _storeService
            .Setup(x => x.GetAsync(It.IsAny<IList<string>>(), It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync((IList<string> ids, string _, bool _) => ids.Contains(StoreId) ? [_store] : []);
    }

    [Fact]
    public void Name_Should_BeTheOtpSignInType()
    {
        // Arrange
        var provider = new OtpStoreAuthenticationTypeProvider(_storeService.Object);

        // Assert
        Assert.Equal(ModuleConstants.Security.SignInType, provider.Name);
        Assert.Equal(ModuleConstants.Security.SignInType, provider.DisplayName);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task IsActiveAsync_Should_ReturnTheStoreSetting(bool enabled)
    {
        // Arrange
        SetStoreSetting(enabled);
        var provider = new OtpStoreAuthenticationTypeProvider(_storeService.Object);

        // Act
        var result = await provider.IsActiveAsync(StoreId);

        // Assert
        Assert.Equal(enabled, result);
    }

    [Fact]
    public async Task IsActiveAsync_Should_ReturnFalse_WhenTheStoreIsNotFound()
    {
        // Arrange
        var provider = new OtpStoreAuthenticationTypeProvider(_storeService.Object);

        // Act
        var result = await provider.IsActiveAsync(UnknownStoreId);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SetIsActiveAsync_Should_SaveTheStoreSetting(bool isActive)
    {
        // Arrange
        SetStoreSetting(!isActive);
        var provider = new OtpStoreAuthenticationTypeProvider(_storeService.Object);

        // Act
        await provider.SetIsActiveAsync(StoreId, isActive);

        // Assert
        Assert.Equal(isActive, _store.Settings.GetValue<bool>(OtpModuleSettings.OtpSignInEnabled));
        _storeService.Verify(x => x.SaveChangesAsync(It.Is<IList<Store>>(stores => stores.Single() == _store)), Times.Once);
    }

    [Fact]
    public async Task SetIsActiveAsync_Should_SaveNothing_WhenTheStoreIsNotFound()
    {
        // Arrange
        var provider = new OtpStoreAuthenticationTypeProvider(_storeService.Object);

        // Act
        await provider.SetIsActiveAsync(UnknownStoreId, true);

        // Assert
        _storeService.Verify(x => x.SaveChangesAsync(It.IsAny<IList<Store>>()), Times.Never);
    }

    private void SetStoreSetting(bool enabled)
    {
        _store.Settings.Add(new ObjectSettingEntry(OtpModuleSettings.OtpSignInEnabled) { Value = enabled });
    }
}
