using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Moq;
using VirtoCommerce.NotificationsModule.Core.Model;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Notifications;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Security.Caching;
using Xunit;

namespace VirtoCommerce.Otp.Tests.Services;

[Trait("Category", "Unit")]
public class OtpServiceTests : OtpTestsBase
{
    [Theory]
    [InlineData(StoreId, TrustedStoreUserEmail, OtpOutcome.Success)]
    [InlineData(StoreId, AdministratorUserEmail, OtpOutcome.Success)]
    [InlineData(StoreId, EmployeeUserEmail, OtpOutcome.Success)]
    [InlineData(UnknownStoreId, ActiveUserEmail, OtpOutcome.StoreNotFound)]
    [InlineData(OtpDisabledStoreId, ActiveUserEmail, OtpOutcome.OtpDisabled)]
    [InlineData(StoreId, UnknownEmail, OtpOutcome.UserNotFound)]
    [InlineData(StoreId, DuplicateEmail, OtpOutcome.DuplicateEmail)]
    [InlineData(StoreId, LockoutDisabledUserEmail, OtpOutcome.LockoutDisabled)]
    [InlineData(StoreId, TemporarilyLockedUserEmail, OtpOutcome.AccountLocked)]
    [InlineData(StoreId, UntrustedStoreUserEmail, OtpOutcome.StoreAccessDenied)]
    [InlineData(StoreId, NoStoreUserEmail, OtpOutcome.StoreAccessDenied)]
    public async Task RequestCodeAsync_Should_ReturnExpectedOutcome(string storeId, string email, OtpOutcome expectedOutcome)
    {
        // Act
        var result = await OtpService.RequestCodeAsync(storeId, email);

        // Assert
        Assert.Equal(expectedOutcome, result.Outcome);
        NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), expectedOutcome == OtpOutcome.Success ? Times.Once() : Times.Never());
    }

    [Theory]
    [InlineData(ActiveUserEmail, ContactLanguage)]
    [InlineData(EmployeeUserEmail, EmployeeLanguage)]
    [InlineData(NoLanguageUserEmail, StoreLanguage)]
    public async Task RequestCodeAsync_Should_SendNotificationInExpectedLanguage(string email, string expectedLanguage)
    {
        // Act
        await OtpService.RequestCodeAsync(StoreId, email);

        // Assert
        NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.Is<Notification>(n => n.LanguageCode == expectedLanguage)), Times.Once);
    }

    [Theory]
    [InlineData(UnknownStoreId)]
    [InlineData(OtpDisabledStoreId)]
    public async Task RequestCodeAsync_Should_NotLookUpUser_When_StoreIsUnavailable(string storeId)
    {
        // Act
        await OtpService.RequestCodeAsync(storeId, ActiveUserEmail);

        // Assert
        UserManager.Verify(x => x.FindByEmailAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_SendCode_When_StoreHasNoSavedOtpScheme()
    {
        // Act
        var result = await OtpService.RequestCodeAsync(NoOtpSchemeStoreId, ActiveUserEmail);

        // Assert
        Assert.Equal(OtpOutcome.Success, result.Outcome);
        NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Once);
    }

    [Theory]
    [InlineData(StoreId)]
    [InlineData(NoOtpSchemeStoreId)]
    public async Task RequestCodeAsync_Should_NotSendCode_When_OtpSignInIsDisabledGlobally(string storeId)
    {
        // Arrange
        SetupOtpSignInEnabled(isEnabled: false);

        // Act
        var result = await OtpService.RequestCodeAsync(storeId, ActiveUserEmail);

        // Assert
        Assert.Equal(OtpOutcome.OtpDisabled, result.Outcome);
        UserManager.Verify(x => x.GenerateUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_Throw_When_StoreIdIsEmpty()
    {
        // Act
        var action = () => OtpService.RequestCodeAsync(string.Empty, ActiveUserEmail);

        // Assert
        await Assert.ThrowsAsync<ArgumentException>(action);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_Throw_When_StoreIdIsEmpty()
    {
        // Act
        var action = () => OtpService.VerifyCodeAsync(string.Empty, ActiveUserEmail, ValidCode);

        // Assert
        await Assert.ThrowsAsync<ArgumentException>(action);
    }

    [Theory]
    [InlineData(StoreId, ActiveUserEmail, ValidCode, OtpOutcome.Success, ActiveUserId)]
    [InlineData(UnknownStoreId, ActiveUserEmail, InvalidCode, OtpOutcome.StoreNotFound, null)]
    [InlineData(OtpDisabledStoreId, ActiveUserEmail, InvalidCode, OtpOutcome.OtpDisabled, null)]
    [InlineData(StoreId, UnknownEmail, ValidCode, OtpOutcome.UserNotFound, null)]
    [InlineData(StoreId, DuplicateEmail, ValidCode, OtpOutcome.DuplicateEmail, null)]
    [InlineData(StoreId, UntrustedStoreUserEmail, ValidCode, OtpOutcome.StoreAccessDenied, UntrustedStoreUserId)]
    public async Task VerifyCodeAsync_Should_ReturnExpectedOutcome(string storeId, string email, string code, OtpOutcome expectedOutcome, string expectedUserId)
    {
        // Act
        var result = await OtpService.VerifyCodeAsync(storeId, email, code);

        // Assert
        Assert.Equal(expectedOutcome, result.Outcome);
        Assert.Equal(expectedUserId, result.User?.Id);
        UserManager.Verify(x => x.ResetAccessFailedCountAsync(It.IsAny<ApplicationUser>()), expectedOutcome == OtpOutcome.Success ? Times.Once() : Times.Never());
    }

    [Theory]
    [InlineData(UnknownStoreId)]
    [InlineData(OtpDisabledStoreId)]
    public async Task VerifyCodeAsync_Should_NotLookUpUser_When_StoreIsUnavailable(string storeId)
    {
        // Act
        await OtpService.VerifyCodeAsync(storeId, ActiveUserEmail, InvalidCode);

        // Assert
        UserManager.Verify(x => x.FindByEmailAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_AcceptCode_When_StoreHasNoSavedOtpScheme()
    {
        // Act
        var result = await OtpService.VerifyCodeAsync(NoOtpSchemeStoreId, ActiveUserEmail, ValidCode);

        // Assert
        Assert.Equal(OtpOutcome.Success, result.Outcome);
        Assert.Equal(ActiveUserId, result.User.Id);
    }

    [Theory]
    [InlineData(StoreId)]
    [InlineData(NoOtpSchemeStoreId)]
    public async Task VerifyCodeAsync_Should_ReturnOtpDisabled_When_OtpSignInIsDisabledGlobally(string storeId)
    {
        // Arrange
        SetupOtpSignInEnabled(isEnabled: false);

        // Act
        var result = await OtpService.VerifyCodeAsync(storeId, ActiveUserEmail, ValidCode);

        // Assert
        Assert.Equal(OtpOutcome.OtpDisabled, result.Outcome);
        UserManager.Verify(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        VerifyCodeStampUpdated(Times.Never());
    }

    [Theory]
    [InlineData(LockoutDisabledUserEmail, OtpOutcome.LockoutDisabled)]
    [InlineData(TemporarilyLockedUserEmail, OtpOutcome.AccountLocked)]
    [InlineData(PermanentlyLockedUserEmail, OtpOutcome.AccountLocked)]
    public async Task VerifyCodeAsync_Should_NotCheckCode_When_UserIsRejectedBeforehand(string email, OtpOutcome expectedOutcome)
    {
        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, email, ValidCode);

        // Assert
        Assert.Equal(expectedOutcome, result.Outcome);
        Assert.Equal(email, result.User.Email);
        UserManager.Verify(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Theory]
    [InlineData(ActiveUserEmail, ActiveUserId)]
    [InlineData(UntrustedStoreUserEmail, UntrustedStoreUserId)]
    public async Task VerifyCodeAsync_Should_RegisterFailedAttempt_When_CodeIsWrong(string email, string expectedUserId)
    {
        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, email, InvalidCode);

        // Assert
        Assert.Equal(OtpOutcome.InvalidCode, result.Outcome);
        Assert.Equal(expectedUserId, result.User.Id);
        UserManager.Verify(x => x.AccessFailedAsync(It.Is<ApplicationUser>(u => u.Id == expectedUserId)), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnInvalidCode_When_FailedAttemptCrossesThreshold()
    {
        // Arrange
        UserManager
            .SetupSequence(x => x.IsLockedOutAsync(ActiveUser))
            .ReturnsAsync(false)
            .ReturnsAsync(false)
            .ReturnsAsync(true);

        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, InvalidCode);

        // Assert
        Assert.Equal(OtpOutcome.InvalidCode, result.Outcome);
        UserManager.Verify(x => x.AccessFailedAsync(ActiveUser), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_RejectCode_When_AlreadyAccepted()
    {
        // Arrange
        await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode);

        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode);

        // Assert
        Assert.Equal(OtpOutcome.InvalidCode, result.Outcome);
        UserManager.Verify(x => x.AccessFailedAsync(ActiveUser), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_AcceptEarlierCode_When_NewCodeRequested()
    {
        // Arrange
        await OtpService.RequestCodeAsync(StoreId, ActiveUserEmail);

        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode);

        // Assert
        Assert.Equal(OtpOutcome.Success, result.Outcome);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_AcceptNewCode_When_PreviousCodeAccepted()
    {
        // Arrange
        string newCode = null;

        NotificationSender
            .Setup(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()))
            .Callback((Notification notification) => newCode = ((OtpSignInEmailNotification)notification).Code);

        await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode);
        await OtpService.RequestCodeAsync(StoreId, ActiveUserEmail);

        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, newCode);

        // Assert
        Assert.NotEqual(ValidCode, newCode);
        Assert.Equal(OtpOutcome.Success, result.Outcome);
    }

    [Theory]
    [InlineData(ActiveUserEmail, ValidCode, true)]
    [InlineData(ActiveUserEmail, InvalidCode, false)]
    [InlineData(UntrustedStoreUserEmail, ValidCode, false)]
    [InlineData(TemporarilyLockedUserEmail, ValidCode, false)]
    public async Task VerifyCodeAsync_Should_UpdateCodeStamp_When_CodeIsAccepted(string email, string code, bool expectedUpdate)
    {
        // Act
        await OtpService.VerifyCodeAsync(StoreId, email, code);

        // Assert
        VerifyCodeStampUpdated(expectedUpdate ? Times.Once() : Times.Never());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task VerifyCodeAsync_Should_Fail_When_CodeStampIsNotUpdated(bool throwsDuplicateEmail)
    {
        // Arrange
        SetupCodeStampFailure(throwsDuplicateEmail);

        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode);

        // Assert
        Assert.Equal(OtpOutcome.CodeStampNotUpdated, result.Outcome);
        UserManager.Verify(x => x.ResetAccessFailedCountAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_AcceptCodeOnce_When_RequestsRunInParallel()
    {
        // Arrange
        UserManager
            .Setup(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), ModuleConstants.Security.TokenProvider, ModuleConstants.Security.TokenPurpose, It.IsAny<string>()))
            .Returns(async (ApplicationUser user, string _, string _, string code) =>
            {
                var codeStamp = CodeStamps[user.Id];
                // Gives the other request time to check the same code before this one changes the code stamp.
                await Task.Delay(100);
                return code == GetCode(codeStamp);
            });

        // Act
        var results = await Task.WhenAll(
            Task.Run(() => OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode)),
            Task.Run(() => OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode)));

        // Assert
        Assert.Single(results, x => x.Outcome == OtpOutcome.Success);
        Assert.Single(results, x => x.Outcome == OtpOutcome.InvalidCode);
    }

    [Theory]
    [InlineData(ActiveUserEmail, ValidCode, true)]
    [InlineData(ActiveUserEmail, InvalidCode, true)]
    [InlineData(UnknownEmail, ValidCode, false)]
    [InlineData(TemporarilyLockedUserEmail, ValidCode, false)]
    public async Task VerifyCodeAsync_Should_LockUser_When_UserIsValid(string email, string code, bool expectedLock)
    {
        // Arrange
        string[] expectedResources = expectedLock ? [$"{ModuleConstants.Security.CodeLockResourcePrefix}:{ActiveUserId}"] : [];

        // Act
        await OtpService.VerifyCodeAsync(StoreId, email, code);

        // Assert
        Assert.Equal(expectedResources, DistributedLock.AcquiredResources);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_NotCheckCode_When_UserLockedOutWhileWaitingForLock()
    {
        // Arrange
        var lockedUser = CreateUser(ActiveUserId, ActiveUserEmail, StoreId, DateTimeOffset.UtcNow.AddSeconds(LockoutSeconds));

        UserManager
            .Setup(x => x.FindByIdAsync(ActiveUserId))
            .ReturnsAsync(lockedUser);

        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode);

        // Assert
        Assert.Equal(OtpOutcome.AccountLocked, result.Outcome);
        UserManager.Verify(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_RegisterFailedAttempt_For_UserReloadedUnderLock()
    {
        // Arrange
        var currentUser = CreateUser(ActiveUserId, ActiveUserEmail, StoreId);

        UserManager
            .Setup(x => x.FindByIdAsync(ActiveUserId))
            .ReturnsAsync(currentUser);

        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, InvalidCode);

        // Assert
        Assert.Same(currentUser, result.User);
        UserManager.Verify(x => x.AccessFailedAsync(currentUser), Times.Once);
        UserManager.Verify(x => x.AccessFailedAsync(ActiveUser), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ExpireCachedUser_Before_ReloadingUnderLock()
    {
        // Arrange
        var cacheToken = SecurityCacheRegion.CreateChangeTokenForUser(ActiveUser);
        bool? isExpiredOnReload = null;

        UserManager
            .Setup(x => x.FindByIdAsync(ActiveUserId))
            .Callback(() => isExpiredOnReload = cacheToken.HasChanged)
            .ReturnsAsync(ActiveUser);

        // Act
        await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode);

        // Assert
        Assert.True(isExpiredOnReload);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnUserNotFound_When_UserDeletedWhileWaitingForLock()
    {
        // Arrange
        UserManager
            .Setup(x => x.FindByIdAsync(ActiveUserId))
            .ReturnsAsync((ApplicationUser)null);

        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode);

        // Assert
        Assert.Equal(OtpOutcome.UserNotFound, result.Outcome);
        UserManager.Verify(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }
}
