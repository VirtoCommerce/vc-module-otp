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

    public async Task<OtpRequestResult> RequestCodeAsync(string email, string storeId = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(email);

        email = email.Trim();

        var user = await ResolveUserAsync(email, storeId);
        if (user != null)
        {
            var effectiveStoreId = storeId ?? user.StoreId;

            if (!await IsOtpSignInEnabledAsync(effectiveStoreId))
            {
                return new OtpRequestResult
                {
                    Outcome = OtpRequestOutcome.OtpDisabled,
                    MaskedEmail = MaskEmail(email),
                };
            }

            var code = await _userManager.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, TokenPurpose);

            await SendCodeNotificationAsync(effectiveStoreId, email, code);
        }

        return new OtpRequestResult
        {
            Outcome = OtpRequestOutcome.CodeSent,
            MaskedEmail = MaskEmail(email),
        };
    }

    public async Task<OtpVerifyResult> VerifyCodeAsync(string email, string code, string storeId = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(email);
        ArgumentException.ThrowIfNullOrEmpty(code);

        email = email.Trim();

        var user = await ResolveUserAsync(email, storeId);
        if (user == null)
        {
            return new OtpVerifyResult
            {
                Outcome = OtpVerifyOutcome.InvalidCode,
            };
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
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
                return new OtpVerifyResult
                {
                    Outcome = OtpVerifyOutcome.AccountLocked,
                    LockoutSecondsRemaining = await GetLockoutSecondsRemainingAsync(user),
                };
            }

            return new OtpVerifyResult
            {
                Outcome = OtpVerifyOutcome.InvalidCode,
            };
        }

        var effectiveStoreId = storeId ?? user.StoreId;
        if (!await IsOtpSignInEnabledAsync(effectiveStoreId))
        {
            return new OtpVerifyResult
            {
                Outcome = OtpVerifyOutcome.OtpDisabled,
            };
        }

        await _userManager.ResetAccessFailedCountAsync(user);

        return new OtpVerifyResult
        {
            Outcome = OtpVerifyOutcome.Success,
            User = user,
        };
    }

    protected virtual async Task<ApplicationUser> ResolveUserAsync(string email, string storeId)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return null;
        }

        if (!string.IsNullOrEmpty(storeId))
        {
            var allowedStoreIds = await _storeService.GetUserAllowedStoreIdsAsync(user);
            if (!allowedStoreIds.Contains(storeId))
            {
                return null;
            }
        }

        return user;
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
