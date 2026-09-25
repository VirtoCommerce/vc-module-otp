using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Moq;
using VirtoCommerce.CustomerModule.Core.Model;
using VirtoCommerce.CustomerModule.Core.Services;
using VirtoCommerce.NotificationsModule.Core.Model;
using VirtoCommerce.NotificationsModule.Core.Services;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Notifications;
using VirtoCommerce.Otp.Data.Services;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Security.Exceptions;
using VirtoCommerce.StoreModule.Core.Model;
using VirtoCommerce.StoreModule.Core.Services;
using Xunit;
using OtpModuleSettings = VirtoCommerce.Otp.Core.ModuleConstants.Settings.General;

namespace VirtoCommerce.Otp.Tests.Services;

[Trait("Category", "Unit")]
public class OtpServiceTests
{
    private const string _storeId = "test-store";
    private const string _missingStoreId = "missing-store";
    private const string _trustedStoreId = "trusted-store";
    private const string _email = "buyer@acme.com";
    private const string _contactId = "contact-1";
    private const string _employeeId = "employee-1";

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnSent_And_SendNotification_When_UserExists()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = _storeId };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose))
            .ReturnsAsync("123456");

        // Act
        var outcome = await context.Service.RequestCodeAsync(_storeId, _email);

        // Assert
        Assert.Equal(OtpRequestOutcome.CodeSent, outcome);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Once);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnSent_When_UserBelongsToATrustedStore()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = _trustedStoreId };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose))
            .ReturnsAsync("123456");

        // Act
        var outcome = await context.Service.RequestCodeAsync(_storeId, _email);

        // Assert
        Assert.Equal(OtpRequestOutcome.CodeSent, outcome);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Once);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnDuplicateEmail_When_EmailBelongsToSeveralUsers()
    {
        // Arrange
        var context = CreateContext();

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ThrowsAsync(new DuplicateEmailException(_email));

        // Act
        var outcome = await context.Service.RequestCodeAsync(_storeId, _email);

        // Assert
        Assert.Equal(OtpRequestOutcome.DuplicateEmail, outcome);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnDuplicateEmail_When_EmailBelongsToSeveralUsers()
    {
        // Arrange
        var context = CreateContext();

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ThrowsAsync(new DuplicateEmailException(_email));

        // Act
        var result = await context.Service.VerifyCodeAsync(_storeId, _email, "123456");

        // Assert
        Assert.Equal(OtpVerifyOutcome.DuplicateEmail, result.Outcome);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnLockoutDisabled_When_UserCannotBeLockedOut()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = _storeId };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.GetLockoutEnabledAsync(user))
            .ReturnsAsync(false);

        // Act
        var outcome = await context.Service.RequestCodeAsync(_storeId, _email);

        // Assert
        Assert.Equal(OtpRequestOutcome.LockoutDisabled, outcome);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnLockoutDisabled_Without_CheckingTheCode_When_UserCannotBeLockedOut()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = _storeId };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.GetLockoutEnabledAsync(user))
            .ReturnsAsync(false);

        // Act
        var result = await context.Service.VerifyCodeAsync(_storeId, _email, "123456");

        // Assert
        Assert.Equal(OtpVerifyOutcome.LockoutDisabled, result.Outcome);
        context.UserManager.Verify(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnStoreAccessDenied_When_UserHasNoStore()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        // Act
        var outcome = await context.Service.RequestCodeAsync(_storeId, _email);

        // Assert
        Assert.Equal(OtpRequestOutcome.StoreAccessDenied, outcome);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnSent_When_AdministratorBelongsToAnotherStore()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = "other-store", IsAdministrator = true };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose))
            .ReturnsAsync("123456");

        // Act
        var outcome = await context.Service.RequestCodeAsync(_storeId, _email);

        // Assert
        Assert.Equal(OtpRequestOutcome.CodeSent, outcome);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnSent_When_NonContactBelongsToAnotherStore()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _employeeId, StoreId = "other-store" };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose))
            .ReturnsAsync("123456");

        // Act
        var outcome = await context.Service.RequestCodeAsync(_storeId, _email);

        // Assert
        Assert.Equal(OtpRequestOutcome.CodeSent, outcome);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnUserNotFound_When_NoUserForEmail()
    {
        // Arrange
        var context = CreateContext();

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync((ApplicationUser)null);

        // Act
        var outcome = await context.Service.RequestCodeAsync(_storeId, _email);

        // Assert
        Assert.Equal(OtpRequestOutcome.UserNotFound, outcome);
        context.UserManager.Verify(x => x.GenerateUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnDisabled_Without_LookingUpTheUser_When_OtpDisabledForStore()
    {
        // Arrange
        var context = CreateContext(enabled: false);

        // Act
        var outcome = await context.Service.RequestCodeAsync(_storeId, _email);

        // Assert
        Assert.Equal(OtpRequestOutcome.OtpDisabled, outcome);
        context.UserManager.Verify(x => x.FindByEmailAsync(It.IsAny<string>()), Times.Never);
        context.UserManager.Verify(x => x.GenerateUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnStoreNotFound_Without_LookingUpTheUser_When_StoreDoesNotExist()
    {
        // Arrange
        var context = CreateContext();

        context.StoreService
            .Setup(x => x.GetAsync(It.Is<IList<string>>(ids => ids.Contains(_missingStoreId)), null, false))
            .ReturnsAsync([]);

        // Act
        var outcome = await context.Service.RequestCodeAsync(_missingStoreId, _email);

        // Assert
        Assert.Equal(OtpRequestOutcome.StoreNotFound, outcome);
        context.UserManager.Verify(x => x.FindByEmailAsync(It.IsAny<string>()), Times.Never);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_ReturnStoreAccessDenied_When_UserBelongsToAnotherStore()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = "other-store" };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        // Act
        var outcome = await context.Service.RequestCodeAsync(_storeId, _email);

        // Assert
        Assert.Equal(OtpRequestOutcome.StoreAccessDenied, outcome);
        context.UserManager.Verify(x => x.GenerateUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        context.NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_Throw_When_StoreIdIsEmpty()
    {
        // Arrange
        var context = CreateContext();

        // Act
        var action = () => context.Service.RequestCodeAsync(string.Empty, _email);

        // Assert
        await Assert.ThrowsAsync<ArgumentException>(action);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnUserNotFound_When_NoUserForEmail()
    {
        // Arrange
        var context = CreateContext();

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync((ApplicationUser)null);

        // Act
        var result = await context.Service.VerifyCodeAsync(_storeId, _email, "123456");

        // Assert
        Assert.Equal(OtpVerifyOutcome.UserNotFound, result.Outcome);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnStoreAccessDenied_When_CodeIsValid_But_UserBelongsToAnotherStore()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = "other-store" };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose, "123456"))
            .ReturnsAsync(true);

        // Act
        var result = await context.Service.VerifyCodeAsync(_storeId, _email, "123456");

        // Assert
        Assert.Equal(OtpVerifyOutcome.StoreAccessDenied, result.Outcome);
        Assert.Same(user, result.User);
        context.UserManager.Verify(x => x.ResetAccessFailedCountAsync(user), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnInvalidCode_When_CodeIsWrong_Even_If_UserBelongsToAnotherStore()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = "other-store" };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose, "000000"))
            .ReturnsAsync(false);

        // Act
        var result = await context.Service.VerifyCodeAsync(_storeId, _email, "000000");

        // Assert
        Assert.Equal(OtpVerifyOutcome.InvalidCode, result.Outcome);
        context.UserManager.Verify(x => x.AccessFailedAsync(user), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnDisabled_Without_CheckingTheCode_When_OtpDisabledForStore()
    {
        // Arrange
        var context = CreateContext(enabled: false);

        // Act
        var result = await context.Service.VerifyCodeAsync(_storeId, _email, "000000");

        // Assert
        Assert.Equal(OtpVerifyOutcome.OtpDisabled, result.Outcome);
        context.UserManager.Verify(x => x.FindByEmailAsync(It.IsAny<string>()), Times.Never);
        context.UserManager.Verify(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        context.UserManager.Verify(x => x.AccessFailedAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnStoreNotFound_Without_CheckingTheCode_When_StoreDoesNotExist()
    {
        // Arrange
        var context = CreateContext();

        context.StoreService
            .Setup(x => x.GetAsync(It.Is<IList<string>>(ids => ids.Contains(_missingStoreId)), null, false))
            .ReturnsAsync([]);

        // Act
        var result = await context.Service.VerifyCodeAsync(_missingStoreId, _email, "000000");

        // Assert
        Assert.Equal(OtpVerifyOutcome.StoreNotFound, result.Outcome);
        context.UserManager.Verify(x => x.FindByEmailAsync(It.IsAny<string>()), Times.Never);
        context.UserManager.Verify(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_Throw_When_StoreIdIsEmpty()
    {
        // Arrange
        var context = CreateContext();

        // Act
        var action = () => context.Service.VerifyCodeAsync(string.Empty, _email, "123456");

        // Assert
        await Assert.ThrowsAsync<ArgumentException>(action);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnLocked_When_AlreadyLockedOut()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = _storeId };
        var lockoutEnd = DateTimeOffset.UtcNow.AddMinutes(10);

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(true);

        context.UserManager
            .Setup(x => x.GetLockoutEndDateAsync(user))
            .ReturnsAsync(lockoutEnd);

        // Act
        var result = await context.Service.VerifyCodeAsync(_storeId, _email, "123456");

        // Assert
        Assert.Equal(OtpVerifyOutcome.AccountLocked, result.Outcome);
        Assert.True(result.LockoutSecondsRemaining > 0);
        Assert.Same(user, result.User);
        context.UserManager.Verify(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnInvalidCode_And_RegisterFailedAttempt_When_CodeDoesNotMatch()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = _storeId };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(false);

        context.UserManager
            .Setup(x => x.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose, "000000"))
            .ReturnsAsync(false);

        // Act
        var result = await context.Service.VerifyCodeAsync(_storeId, _email, "000000");

        // Assert
        Assert.Equal(OtpVerifyOutcome.InvalidCode, result.Outcome);
        context.UserManager.Verify(x => x.AccessFailedAsync(user), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnInvalidCode_When_FailedAttemptCrossesTheThreshold()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = _storeId };

        context.UserManager
            .SetupSequence(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(false)
            .ReturnsAsync(true);

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose, "000000"))
            .ReturnsAsync(false);

        // Act
        var result = await context.Service.VerifyCodeAsync(_storeId, _email, "000000");

        // Assert
        Assert.Equal(OtpVerifyOutcome.InvalidCode, result.Outcome);
        context.UserManager.Verify(x => x.AccessFailedAsync(user), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnSuccess_And_ResetFailedCount_When_CodeMatches()
    {
        // Arrange
        var context = CreateContext();
        var user = new ApplicationUser { Email = _email, MemberId = _contactId, StoreId = _storeId };

        context.UserManager
            .Setup(x => x.FindByEmailAsync(_email))
            .ReturnsAsync(user);

        context.UserManager
            .Setup(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(false);

        context.UserManager
            .Setup(x => x.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, OtpService.TokenPurpose, "654321"))
            .ReturnsAsync(true);

        // Act
        var result = await context.Service.VerifyCodeAsync(_storeId, _email, "654321");

        // Assert
        Assert.Equal(OtpVerifyOutcome.Success, result.Outcome);
        context.UserManager.Verify(x => x.ResetAccessFailedCountAsync(user), Times.Once);
    }

    private static TestContext CreateContext(bool enabled = true)
    {
        var store = new Store
        {
            Id = _storeId,
            TrustedGroups = [_trustedStoreId],
            Settings =
            [
                new() { Name = OtpModuleSettings.OtpSignInEnabled.Name, Value = enabled },
            ],
        };

        var storeService = new Mock<IStoreService>();

        storeService
            .Setup(x => x.GetAsync(It.Is<IList<string>>(ids => ids.Contains(_storeId)), null, false))
            .ReturnsAsync([store]);

        var memberService = new Mock<IMemberService>();

        memberService
            .Setup(x => x.GetByIdAsync(_contactId, null, null))
            .ReturnsAsync(new Contact { Id = _contactId });

        memberService
            .Setup(x => x.GetByIdAsync(_employeeId, null, null))
            .ReturnsAsync(new Employee { Id = _employeeId });

        var userStore = new Mock<IUserStore<ApplicationUser>>();
        var userManager = new Mock<UserManager<ApplicationUser>>(userStore.Object, null, null, null, null, null, null, null, null);

        userManager
            .Setup(x => x.GetLockoutEnabledAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(true);

        var notificationSearchService = new Mock<INotificationSearchService>();

        notificationSearchService
            .Setup(x => x.SearchNotificationsAsync(It.IsAny<NotificationSearchCriteria>()))
            .ReturnsAsync(new NotificationSearchResult { Results = [new OtpSignInEmailNotification()] });

        var notificationSender = new Mock<INotificationSender>();

        var service = new OtpService(
            userManager.Object,
            storeService.Object,
            memberService.Object,
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
