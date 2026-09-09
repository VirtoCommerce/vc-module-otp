using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Moq;
using VirtoCommerce.NotificationsModule.Core.Model;
using VirtoCommerce.NotificationsModule.Core.Services;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Notifications;
using VirtoCommerce.Otp.Data.Services;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Core.Settings;
using Xunit;
using StoreSettings = VirtoCommerce.Otp.Core.ModuleConstants.Settings.General;

namespace VirtoCommerce.Otp.Tests.Services;

[Trait("Category", "Unit")]
public class OtpServiceTests
{
    private const string StoreId = "test-store";
    private const string Email = "buyer@acme.com";
    private const string TokenProvider = "Email";
    private const string TokenPurpose = "OtpSignIn";

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnDisabled_When_OtpDisabledForStore()
    {
        var context = CreateContext(enabled: false);

        var result = await context.Service.RequestCodeAsync(StoreId, Email);

        Assert.Equal(OtpRequestOutcome.Disabled, result.Outcome);
        context.UserManager.Verify(x => x.FindByEmailAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnSent_And_SendNotification_When_UserExists()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = Email };
        context.UserManager.Setup(x => x.FindByEmailAsync(Email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.GenerateUserTokenAsync(user, TokenProvider, TokenPurpose)).ReturnsAsync("123456");

        var result = await context.Service.RequestCodeAsync(StoreId, Email);

        Assert.Equal(OtpRequestOutcome.Sent, result.Outcome);
        Assert.Equal("b•••r@acme.com", result.MaskedEmail);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Once);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnSent_But_SkipGeneration_When_NoUserForEmail()
    {
        // Anti-enumeration: the response is identical to the "user exists" case, but nothing is generated
        // or sent, since Identity's token APIs require an actual user to operate on.
        var context = CreateContext();
        context.UserManager.Setup(x => x.FindByEmailAsync(Email)).ReturnsAsync((ApplicationUser)null);

        var result = await context.Service.RequestCodeAsync(StoreId, Email);

        Assert.Equal(OtpRequestOutcome.Sent, result.Outcome);
        context.UserManager.Verify(x => x.GenerateUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnDisabled_When_OtpDisabledForStore()
    {
        var context = CreateContext(enabled: false);

        var result = await context.Service.VerifyCodeAsync(StoreId, Email, "123456");

        Assert.Equal(OtpVerifyOutcome.Disabled, result.Outcome);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnInvalidCode_When_NoUserForEmail()
    {
        // Anti-enumeration: an unknown email must be indistinguishable from a wrong code, otherwise this
        // endpoint (unlike RequestCodeAsync) could be used to check whether an email is registered.
        var context = CreateContext();
        context.UserManager.Setup(x => x.FindByEmailAsync(Email)).ReturnsAsync((ApplicationUser)null);

        var result = await context.Service.VerifyCodeAsync(StoreId, Email, "123456");

        Assert.Equal(OtpVerifyOutcome.InvalidCode, result.Outcome);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnLocked_When_AlreadyLockedOut()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = Email };
        var lockoutEnd = DateTimeOffset.UtcNow.AddMinutes(10);
        context.UserManager.Setup(x => x.FindByEmailAsync(Email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(true);
        context.UserManager.Setup(x => x.GetLockoutEndDateAsync(user)).ReturnsAsync(lockoutEnd);

        var result = await context.Service.VerifyCodeAsync(StoreId, Email, "123456");

        Assert.Equal(OtpVerifyOutcome.Locked, result.Outcome);
        Assert.True(result.LockoutSecondsRemaining > 0);
        context.UserManager.Verify(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnInvalidCode_And_RegisterFailedAttempt_When_CodeDoesNotMatch()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = Email };
        context.UserManager.Setup(x => x.FindByEmailAsync(Email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        context.UserManager.Setup(x => x.VerifyUserTokenAsync(user, TokenProvider, TokenPurpose, "000000")).ReturnsAsync(false);

        var result = await context.Service.VerifyCodeAsync(StoreId, Email, "000000");

        Assert.Equal(OtpVerifyOutcome.InvalidCode, result.Outcome);
        context.UserManager.Verify(x => x.AccessFailedAsync(user), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnLocked_When_FailedAttemptCrossesTheThreshold()
    {
        // Shared with password sign-in by design: the platform's standard IdentityOptions.Lockout already
        // gates repeated wrong guesses, so IsLockedOutAsync flips to true right after AccessFailedAsync.
        var context = CreateContext();
        var user = new ApplicationUser { Email = Email };
        var lockoutEnd = DateTimeOffset.UtcNow.AddMinutes(15);
        context.UserManager.SetupSequence(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(false)
            .ReturnsAsync(true);
        context.UserManager.Setup(x => x.FindByEmailAsync(Email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.VerifyUserTokenAsync(user, TokenProvider, TokenPurpose, "000000")).ReturnsAsync(false);
        context.UserManager.Setup(x => x.GetLockoutEndDateAsync(user)).ReturnsAsync(lockoutEnd);

        var result = await context.Service.VerifyCodeAsync(StoreId, Email, "000000");

        Assert.Equal(OtpVerifyOutcome.Locked, result.Outcome);
        Assert.True(result.LockoutSecondsRemaining > 0);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnSuccess_And_ResetFailedCount_When_CodeMatches()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = Email };
        context.UserManager.Setup(x => x.FindByEmailAsync(Email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        context.UserManager.Setup(x => x.VerifyUserTokenAsync(user, TokenProvider, TokenPurpose, "654321")).ReturnsAsync(true);

        var result = await context.Service.VerifyCodeAsync(StoreId, Email, "654321");

        Assert.Equal(OtpVerifyOutcome.Success, result.Outcome);
        context.UserManager.Verify(x => x.ResetAccessFailedCountAsync(user), Times.Once);
    }

    private static TestContext CreateContext(bool enabled = true)
    {
        var settingValues = new Dictionary<string, object>
        {
            [StoreSettings.Enabled.Name] = enabled,
        };

        var settingsManager = new Mock<ISettingsManager>();
        settingsManager
            .Setup(x => x.GetObjectSettingAsync(It.IsAny<string>(), "Store", StoreId))
            .ReturnsAsync((string name, string _, string _) => new ObjectSettingEntry
            {
                Name = name,
                Value = settingValues.GetValueOrDefault(name),
            });

        var userStore = new Mock<IUserStore<ApplicationUser>>();
        var userManager = new Mock<UserManager<ApplicationUser>>(userStore.Object, null, null, null, null, null, null, null, null);

        var notificationSearchService = new Mock<INotificationSearchService>();
        notificationSearchService
            .Setup(x => x.SearchNotificationsAsync(It.IsAny<NotificationSearchCriteria>()))
            .ReturnsAsync(new NotificationSearchResult { Results = [new OtpSignInEmailNotification()] });

        var notificationSender = new Mock<INotificationSender>();

        var service = new OtpService(
            userManager.Object,
            settingsManager.Object,
            notificationSearchService.Object,
            notificationSender.Object);

        return new TestContext(service, userManager, settingsManager, notificationSender);
    }

    private sealed record TestContext(
        OtpService Service,
        Mock<UserManager<ApplicationUser>> UserManager,
        Mock<ISettingsManager> SettingsManager,
        Mock<INotificationSender> NotificationSender);
}
