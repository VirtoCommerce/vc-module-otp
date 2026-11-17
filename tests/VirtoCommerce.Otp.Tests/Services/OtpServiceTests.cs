using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Moq;
using VirtoCommerce.NotificationsModule.Core.Model;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Platform.Core.Security;
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
    public async Task RequestCodeAsync_Should_SendTheNotificationInTheExpectedLanguage(string email, string expectedLanguage)
    {
        // Act
        await OtpService.RequestCodeAsync(StoreId, email);

        // Assert
        NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.Is<Notification>(n => n.LanguageCode == expectedLanguage)), Times.Once);
    }

    [Theory]
    [InlineData(UnknownStoreId)]
    [InlineData(OtpDisabledStoreId)]
    public async Task RequestCodeAsync_Should_NotLookUpTheUser_When_StoreIsUnavailable(string storeId)
    {
        // Act
        await OtpService.RequestCodeAsync(storeId, ActiveUserEmail);

        // Assert
        UserManager.Verify(x => x.FindByEmailAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task RequestCodeAsync_Should_Throw_When_StoreIdIsEmpty()
    {
        // Act
        var action = () => OtpService.RequestCodeAsync(string.Empty, ActiveUserEmail);

        // Assert
        await Assert.ThrowsAsync<ArgumentException>(action);
    }

    [Theory]
    [InlineData(StoreId, ActiveUserEmail, true)]
    [InlineData(StoreId, UntrustedStoreUserEmail, false)]
    [InlineData(OtpDisabledStoreId, ActiveUserEmail, false)]
    public async Task RequestCodeAsync_Should_UpdateTheCodeStamp_When_TheCodeIsSent(string storeId, string email, bool expectedUpdate)
    {
        // Act
        await OtpService.RequestCodeAsync(storeId, email);

        // Assert
        VerifyCodeStampUpdated(expectedUpdate ? Times.Once() : Times.Never());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RequestCodeAsync_Should_NotSendTheCode_When_TheCodeStampIsNotUpdated(bool throwsDuplicateEmail)
    {
        // Arrange
        SetUpCodeStampFailure(throwsDuplicateEmail);

        // Act
        var result = await OtpService.RequestCodeAsync(StoreId, ActiveUserEmail);

        // Assert
        Assert.Equal(OtpOutcome.CodeStampNotUpdated, result.Outcome);
        UserManager.Verify(x => x.GenerateUserTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        NotificationSender.Verify(x => x.ScheduleSendNotificationAsync(It.IsAny<Notification>()), Times.Never);
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
    public async Task VerifyCodeAsync_Should_NotLookUpTheUser_When_StoreIsUnavailable(string storeId)
    {
        // Act
        await OtpService.VerifyCodeAsync(storeId, ActiveUserEmail, InvalidCode);

        // Assert
        UserManager.Verify(x => x.FindByEmailAsync(It.IsAny<string>()), Times.Never);
    }

    [Theory]
    [InlineData(LockoutDisabledUserEmail, OtpOutcome.LockoutDisabled)]
    [InlineData(TemporarilyLockedUserEmail, OtpOutcome.AccountLocked)]
    [InlineData(PermanentlyLockedUserEmail, OtpOutcome.AccountLocked)]
    public async Task VerifyCodeAsync_Should_NotCheckTheCode_When_UserIsRejectedBeforehand(string email, OtpOutcome expectedOutcome)
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
    public async Task VerifyCodeAsync_Should_RegisterAFailedAttempt_When_CodeIsWrong(string email, string expectedUserId)
    {
        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, email, InvalidCode);

        // Assert
        Assert.Equal(OtpOutcome.InvalidCode, result.Outcome);
        Assert.Equal(expectedUserId, result.User.Id);
        UserManager.Verify(x => x.AccessFailedAsync(It.Is<ApplicationUser>(u => u.Id == expectedUserId)), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_ReturnInvalidCode_When_FailedAttemptCrossesTheThreshold()
    {
        // Arrange
        UserManager
            .SetupSequence(x => x.IsLockedOutAsync(ActiveUser))
            .ReturnsAsync(false)
            .ReturnsAsync(true);

        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, InvalidCode);

        // Assert
        Assert.Equal(OtpOutcome.InvalidCode, result.Outcome);
        UserManager.Verify(x => x.AccessFailedAsync(ActiveUser), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_RejectTheCode_When_ItWasAlreadyAccepted()
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
    public async Task VerifyCodeAsync_Should_RejectTheCode_When_ANewCodeWasRequested()
    {
        // Arrange
        await OtpService.RequestCodeAsync(StoreId, ActiveUserEmail);

        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode);

        // Assert
        Assert.Equal(OtpOutcome.InvalidCode, result.Outcome);
    }

    [Theory]
    [InlineData(ActiveUserEmail, ValidCode, true)]
    [InlineData(ActiveUserEmail, InvalidCode, false)]
    [InlineData(UntrustedStoreUserEmail, ValidCode, false)]
    [InlineData(TemporarilyLockedUserEmail, ValidCode, false)]
    public async Task VerifyCodeAsync_Should_UpdateTheCodeStamp_When_TheCodeIsAccepted(string email, string code, bool expectedUpdate)
    {
        // Act
        await OtpService.VerifyCodeAsync(StoreId, email, code);

        // Assert
        VerifyCodeStampUpdated(expectedUpdate ? Times.Once() : Times.Never());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task VerifyCodeAsync_Should_Fail_When_TheCodeStampIsNotUpdated(bool throwsDuplicateEmail)
    {
        // Arrange
        SetUpCodeStampFailure(throwsDuplicateEmail);

        // Act
        var result = await OtpService.VerifyCodeAsync(StoreId, ActiveUserEmail, ValidCode);

        // Assert
        Assert.Equal(OtpOutcome.CodeStampNotUpdated, result.Outcome);
        UserManager.Verify(x => x.ResetAccessFailedCountAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_AcceptTheCodeOnce_When_RequestsRunInParallel()
    {
        // Arrange
        UserManager
            .Setup(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), ModuleConstants.Security.TokenProvider, ModuleConstants.Security.TokenPurpose, It.IsAny<string>()))
            .Returns(async (ApplicationUser user, string _, string _, string code) =>
            {
                var codeStamp = CodeStamps.GetValueOrDefault(user.Id);
                // Gives the other request time to check the same code before this one changes the code stamp.
                await Task.Delay(100);
                return code == ValidCode && codeStamp == ValidCodeStamp;
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
    public async Task VerifyCodeAsync_Should_LockTheUser_When_TheUserIsValid(string email, string code, bool expectedLock)
    {
        // Arrange
        string[] expectedResources = expectedLock ? [$"{ModuleConstants.Security.CodeLockResourcePrefix}:{ActiveUserId}"] : [];

        // Act
        await OtpService.VerifyCodeAsync(StoreId, email, code);

        // Assert
        Assert.Equal(expectedResources, DistributedLock.AcquiredResources);
    }
}
