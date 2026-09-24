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
using VirtoCommerce.StoreModule.Core.Model;
using VirtoCommerce.StoreModule.Core.Services;
using Xunit;
using OtpModuleSettings = VirtoCommerce.Otp.Core.ModuleConstants.Settings.General;

namespace VirtoCommerce.Otp.Tests.Services;

[Trait("Category", "Unit")]
public class OtpServiceTests
{
    private const string _storeId = "test-store";
    private const string _email = "buyer@acme.com";

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnSent_And_SendNotification_When_UserExists()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose)).ReturnsAsync("123456");

        var result = await context.Service.RequestCodeAsync(_email);

        Assert.Equal(OtpRequestOutcome.CodeSent, result.Outcome);
        Assert.Equal("b•••r@acme.com", result.MaskedEmail);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Once);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnUserNotFound_When_NoUserForEmail()
    {
        var context = CreateContext();
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync((ApplicationUser)null);

        var result = await context.Service.RequestCodeAsync(_email);

        Assert.Equal(OtpRequestOutcome.UserNotFound, result.Outcome);
        context.UserManager.Verify(x => x.GenerateUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnDisabled_But_SkipGeneration_When_OtpDisabledForUsersStore()
    {
        var context = CreateContext(enabled: false);
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);

        var result = await context.Service.RequestCodeAsync(_email);

        Assert.Equal(OtpRequestOutcome.OtpDisabled, result.Outcome);
        context.UserManager.Verify(x => x.GenerateUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_UseTheUsersOwnStore_Not_ACallerSuppliedOne()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose)).ReturnsAsync("123456");

        var result = await context.Service.RequestCodeAsync(_email);

        Assert.Equal(OtpRequestOutcome.CodeSent, result.Outcome);
        context.StoreService.Verify(x => x.GetAsync(It.Is<IList<string>>(ids => ids.Contains(_storeId)), null, false), Times.Once);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnUserNotFound_When_StoreIdDoesNotMatchTheUsersStore()
    {
        // A caller-supplied storeId can only narrow the match, never widen it - a mismatch looks
        // exactly like "no such user" rather than revealing the account belongs to another store.
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);

        var result = await context.Service.RequestCodeAsync(_email, storeId: "other-store");

        Assert.Equal(OtpRequestOutcome.UserNotFound, result.Outcome);
        context.UserManager.Verify(x => x.GenerateUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_SendNotification_When_StoreIdMatchesTheUsersStore()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose)).ReturnsAsync("123456");

        var result = await context.Service.RequestCodeAsync(_email, storeId: _storeId);

        Assert.Equal(OtpRequestOutcome.CodeSent, result.Outcome);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Once);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_UseTheUsersOwnStore_When_StoreIdIsEmpty()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose)).ReturnsAsync("123456");

        var result = await context.Service.RequestCodeAsync(_email, storeId: string.Empty);

        Assert.Equal(OtpRequestOutcome.CodeSent, result.Outcome);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnInvalidCode_When_NoUserForEmail()
    {
        // Anti-enumeration: an unknown email must look the same as a wrong code.
        var context = CreateContext();
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync((ApplicationUser)null);

        var result = await context.Service.VerifyCodeAsync(_email, "123456");

        Assert.Equal(OtpVerifyOutcome.InvalidCode, result.Outcome);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnInvalidCode_When_StoreIdDoesNotMatchTheUsersStore()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);

        var result = await context.Service.VerifyCodeAsync(_email, "123456", storeId: "other-store");

        Assert.Equal(OtpVerifyOutcome.InvalidCode, result.Outcome);
        context.UserManager.Verify(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnDisabled_When_CodeIsValid_But_OtpDisabledForUsersStore()
    {
        var context = CreateContext(enabled: false);
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        context.UserManager.Setup(x => x.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose, "123456")).ReturnsAsync(true);

        var result = await context.Service.VerifyCodeAsync(_email, "123456");

        Assert.Equal(OtpVerifyOutcome.OtpDisabled, result.Outcome);
        Assert.Same(user, result.User);
        context.UserManager.Verify(x => x.ResetAccessFailedCountAsync(user), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_UseTheUsersOwnStore_When_StoreIdIsEmpty()
    {
        var context = CreateContext(enabled: false);
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        context.UserManager.Setup(x => x.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose, "123456")).ReturnsAsync(true);

        var result = await context.Service.VerifyCodeAsync(_email, "123456", storeId: string.Empty);

        Assert.Equal(OtpVerifyOutcome.OtpDisabled, result.Outcome);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnInvalidCode_When_CodeIsWrong_Even_If_OtpDisabledForUsersStore()
    {
        var context = CreateContext(enabled: false);
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        context.UserManager.Setup(x => x.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose, "000000")).ReturnsAsync(false);

        var result = await context.Service.VerifyCodeAsync(_email, "000000");

        Assert.Equal(OtpVerifyOutcome.InvalidCode, result.Outcome);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnLocked_When_AlreadyLockedOut()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        var lockoutEnd = DateTimeOffset.UtcNow.AddMinutes(10);
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(true);
        context.UserManager.Setup(x => x.GetLockoutEndDateAsync(user)).ReturnsAsync(lockoutEnd);

        var result = await context.Service.VerifyCodeAsync(_email, "123456");

        Assert.Equal(OtpVerifyOutcome.AccountLocked, result.Outcome);
        Assert.True(result.LockoutSecondsRemaining > 0);
        Assert.Same(user, result.User);
        context.UserManager.Verify(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnInvalidCode_And_RegisterFailedAttempt_When_CodeDoesNotMatch()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        context.UserManager.Setup(x => x.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose, "000000")).ReturnsAsync(false);

        var result = await context.Service.VerifyCodeAsync(_email, "000000");

        Assert.Equal(OtpVerifyOutcome.InvalidCode, result.Outcome);
        context.UserManager.Verify(x => x.AccessFailedAsync(user), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnLocked_When_FailedAttemptCrossesTheThreshold()
    {
        // Lockout is the platform's shared IdentityOptions.Lockout, not OTP-specific logic.
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        var lockoutEnd = DateTimeOffset.UtcNow.AddMinutes(15);
        context.UserManager.SetupSequence(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(false)
            .ReturnsAsync(true);
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose, "000000")).ReturnsAsync(false);
        context.UserManager.Setup(x => x.GetLockoutEndDateAsync(user)).ReturnsAsync(lockoutEnd);

        var result = await context.Service.VerifyCodeAsync(_email, "000000");

        Assert.Equal(OtpVerifyOutcome.AccountLocked, result.Outcome);
        Assert.True(result.LockoutSecondsRemaining > 0);
        Assert.Same(user, result.User);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnSuccess_And_ResetFailedCount_When_CodeMatches()
    {
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, StoreId = _storeId };
        context.UserManager.Setup(x => x.FindByEmailAsync(_email)).ReturnsAsync(user);
        context.UserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        context.UserManager.Setup(x => x.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose, "654321")).ReturnsAsync(true);

        var result = await context.Service.VerifyCodeAsync(_email, "654321");

        Assert.Equal(OtpVerifyOutcome.Success, result.Outcome);
        context.UserManager.Verify(x => x.ResetAccessFailedCountAsync(user), Times.Once);
    }

    private static TestContext CreateContext(bool enabled = true)
    {
        var store = new Store
        {
            Id = _storeId,
            Settings =
            [
                new() { Name = OtpModuleSettings.OtpSignInEnabled.Name, Value = enabled },
            ],
        };

        var storeService = new Mock<IStoreService>();
        storeService
            .Setup(x => x.GetAsync(It.Is<IList<string>>(ids => ids.Contains(_storeId)), null, false))
            .ReturnsAsync([store]);
        storeService
            .Setup(x => x.GetUserAllowedStoreIdsAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync([_storeId]);

        var userStore = new Mock<IUserStore<ApplicationUser>>();
        var userManager = new Mock<UserManager<ApplicationUser>>(userStore.Object, null, null, null, null, null, null, null, null);

        var notificationSearchService = new Mock<INotificationSearchService>();
        notificationSearchService
            .Setup(x => x.SearchNotificationsAsync(It.IsAny<NotificationSearchCriteria>()))
            .ReturnsAsync(new NotificationSearchResult { Results = [new OtpSignInEmailNotification()] });

        var notificationSender = new Mock<INotificationSender>();

        var service = new OtpService(
            userManager.Object,
            storeService.Object,
            notificationSearchService.Object,
            notificationSender.Object);

        return new TestContext(service, userManager, storeService, notificationSender);
    }

    private sealed record TestContext(
        OtpService Service,
        Mock<UserManager<ApplicationUser>> UserManager,
        Mock<IStoreService> StoreService,
        Mock<INotificationSender> NotificationSender);
}
