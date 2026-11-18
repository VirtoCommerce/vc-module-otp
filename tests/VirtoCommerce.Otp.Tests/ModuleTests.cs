using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Data.Providers;
using VirtoCommerce.Otp.Web;
using VirtoCommerce.Platform.Core.Security;
using Xunit;

namespace VirtoCommerce.Otp.Tests;

[Trait("Category", "Unit")]
public class ModuleTests
{
    [Fact]
    public void Initialize_Should_RegisterOtpTokenProvider_And_KeepIdentityEmailProvider()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddIdentityCore<ApplicationUser>().AddDefaultTokenProviders();

        // Act
        new Module().Initialize(services);
        using var serviceProvider = services.BuildServiceProvider();

        // Assert
        var providerMap = serviceProvider.GetRequiredService<IOptions<IdentityOptions>>().Value.Tokens.ProviderMap;
        var providerType = providerMap[ModuleConstants.Security.TokenProvider].ProviderType;
        Assert.Equal(typeof(OtpEmailTokenProvider), providerType);
        Assert.IsType<OtpEmailTokenProvider>(serviceProvider.GetRequiredService(providerType));
        Assert.Equal(typeof(EmailTokenProvider<ApplicationUser>), providerMap[TokenOptions.DefaultEmailProvider].ProviderType);
    }
}
