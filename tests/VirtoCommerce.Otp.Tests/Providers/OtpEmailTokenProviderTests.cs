using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Moq;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Data.Providers;
using VirtoCommerce.Platform.Core.Security;
using Xunit;

namespace VirtoCommerce.Otp.Tests.Providers;

[Trait("Category", "Unit")]
public class OtpEmailTokenProviderTests
{
    private const string Purpose = ModuleConstants.Security.TokenPurpose;

    private readonly ApplicationUser _user = new() { Id = "user-1", Email = "john.smith@acme.com", SecurityStamp = "security-stamp" };
    private readonly Dictionary<string, string> _codeStamps = [];
    private readonly Mock<UserManager<ApplicationUser>> _userManager;
    private readonly OtpEmailTokenProvider _provider = new();

    public OtpEmailTokenProviderTests()
    {
        _userManager = new Mock<UserManager<ApplicationUser>>(Mock.Of<IUserStore<ApplicationUser>>(), null, null, null, null, null, null, null, null);

        _userManager
            .Setup(x => x.GetEmailAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync((ApplicationUser user) => user.Email);

        _userManager
            .Setup(x => x.CreateSecurityTokenAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync((ApplicationUser user) => Encoding.Unicode.GetBytes(user.SecurityStamp));

        _userManager
            .Setup(x => x.GetAuthenticationTokenAsync(It.IsAny<ApplicationUser>(), ModuleConstants.Security.CodeStampLoginProvider, ModuleConstants.Security.CodeStampName))
            .ReturnsAsync((ApplicationUser user, string _, string _) => _codeStamps.GetValueOrDefault(user.Id));
    }

    [Fact]
    public async Task ValidateAsync_Should_AcceptCode_When_CodeStampIsSame()
    {
        // Arrange
        _codeStamps[_user.Id] = "first-stamp";
        var code = await _provider.GenerateAsync(Purpose, _userManager.Object, _user);

        // Act
        var isValid = await _provider.ValidateAsync(Purpose, code, _userManager.Object, _user);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public async Task ValidateAsync_Should_RejectCode_When_CodeStampChanged()
    {
        // Arrange
        _codeStamps[_user.Id] = "first-stamp";
        var code = await _provider.GenerateAsync(Purpose, _userManager.Object, _user);
        _codeStamps[_user.Id] = "second-stamp";

        // Act
        var isValid = await _provider.ValidateAsync(Purpose, code, _userManager.Object, _user);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public async Task GetUserModifierAsync_Should_AddCodeStamp()
    {
        // Arrange
        _codeStamps[_user.Id] = "first-stamp";

        // Act
        var modifier = await _provider.GetUserModifierAsync(Purpose, _userManager.Object, _user);

        // Assert
        Assert.Equal($"Email:{Purpose}:{_user.Email}:first-stamp", modifier);
    }
}
