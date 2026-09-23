using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using VirtoCommerce.NotificationsModule.Core.Extensions;
using VirtoCommerce.NotificationsModule.Core.Services;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Notifications;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Platform.Core.Common;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Core.Settings;
using VirtoCommerce.StoreModule.Core.Model;
using VirtoCommerce.StoreModule.Core.Services;
using OtpModuleSettings = VirtoCommerce.Otp.Core.ModuleConstants.Settings.General;

namespace VirtoCommerce.Otp.Data.Services;

public class OtpService : IOtpService
{
    public const string TokenPurpose = "OtpSignIn";

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IStoreService _storeService;
    private readonly INotificationSearchService _notificationSearchService;
    private readonly INotificationSender _notificationSender;

    public OtpService(
        UserManager<ApplicationUser> userManager,
        IStoreService storeService,
        INotificationSearchService notificationSearchService,
        INotificationSender notificationSender)
    {
        _userManager = userManager;
        _storeService = storeService;
        _notificationSearchService = notificationSearchService;
        _notificationSender = notificationSender;
    }

    public async Task<OtpRequestResult> RequestCodeAsync(string storeId, string email)
    {
        ArgumentException.ThrowIfNullOrEmpty(storeId);
        ArgumentException.ThrowIfNullOrEmpty(email);

        var delayedResponse = DelayedResponse.Create(nameof(OtpService), nameof(RequestCodeAsync));

        var otpEnabled = await IsOtpSignInEnabledAsync(storeId);
        if (!otpEnabled)
        {
            await delayedResponse.FailAsync();

            return new OtpRequestResult
            {
                Outcome = OtpRequestOutcome.OtpDisabled,
            };
        }

        email = email.Trim();

        var user = await _userManager.FindByEmailAsync(email);
        if (user != null)
        {
            var code = await _userManager.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, TokenPurpose);

            await SendCodeNotificationAsync(storeId, email, code);
        }

        await delayedResponse.SucceedAsync();

        return new OtpRequestResult
        {
            Outcome = OtpRequestOutcome.CodeSent,
            MaskedEmail = MaskEmail(email),
        };
    }

    public async Task<OtpVerifyResult> VerifyCodeAsync(string storeId, string email, string code)
    {
        ArgumentException.ThrowIfNullOrEmpty(storeId);
        ArgumentException.ThrowIfNullOrEmpty(email);
        ArgumentException.ThrowIfNullOrEmpty(code);

        var otpEnabled = await IsOtpSignInEnabledAsync(storeId);
        if (!otpEnabled)
        {
            return new OtpVerifyResult
            {
                Outcome = OtpVerifyOutcome.OtpDisabled,
            };
        }

        var delayedResponse = DelayedResponse.Create(nameof(OtpService), nameof(VerifyCodeAsync));

        email = email.Trim();

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            await delayedResponse.FailAsync();

            return new OtpVerifyResult
            {
                Outcome = OtpVerifyOutcome.InvalidCode,
            };
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            await delayedResponse.FailAsync();

            return new OtpVerifyResult
            {
                Outcome = OtpVerifyOutcome.AccountLocked,
                LockoutSecondsRemaining = await GetLockoutSecondsRemainingAsync(user),
            };
        }

        var isValid = await _userManager.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, TokenPurpose, code);
        if (!isValid)
        {
            await _userManager.AccessFailedAsync(user);

            if (await _userManager.IsLockedOutAsync(user))
            {
                await delayedResponse.FailAsync();

                return new OtpVerifyResult
                {
                    Outcome = OtpVerifyOutcome.AccountLocked,
                    LockoutSecondsRemaining = await GetLockoutSecondsRemainingAsync(user),
                };
            }

            await delayedResponse.FailAsync();

            return new OtpVerifyResult
            {
                Outcome = OtpVerifyOutcome.InvalidCode,
            };
        }

        await _userManager.ResetAccessFailedCountAsync(user);

        await delayedResponse.SucceedAsync();

        return new OtpVerifyResult
        {
            Outcome = OtpVerifyOutcome.Success,
            User = user,
        };
    }

    protected virtual async Task<int?> GetLockoutSecondsRemainingAsync(ApplicationUser user)
    {
        var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
        if (lockoutEnd == null)
        {
            return null;
        }

        return (int)Math.Max(0, Math.Ceiling((lockoutEnd.Value - DateTimeOffset.UtcNow).TotalSeconds));
    }

    protected virtual async Task SendCodeNotificationAsync(string storeId, string email, string code)
    {
        var notification = await _notificationSearchService.GetNotificationAsync<OtpSignInEmailNotification>(new TenantIdentity(storeId, nameof(Store)));

        notification.To = email;
        notification.Code = code;

        await _notificationSender.ScheduleSendNotificationAsync(notification);
    }

    protected virtual async Task<bool> IsOtpSignInEnabledAsync(string storeId)
    {
        var store = await _storeService.GetNoCloneAsync(storeId);

        return store?.Settings.GetValue<bool>(OtpModuleSettings.OtpSignInEnabled) ?? false;
    }

    protected virtual string MaskEmail(string email)
    {
        var atIndex = email.IndexOf('@');
        if (atIndex <= 1)
        {
            return email;
        }

        var localPart = email[..atIndex];
        var domainPart = email[atIndex..];

        return $"{localPart[0]}•••{localPart[^1]}{domainPart}";
    }
}
