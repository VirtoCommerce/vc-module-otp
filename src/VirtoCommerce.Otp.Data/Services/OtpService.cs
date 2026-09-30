using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using VirtoCommerce.CustomerModule.Core.Model;
using VirtoCommerce.CustomerModule.Core.Services;
using VirtoCommerce.NotificationsModule.Core.Extensions;
using VirtoCommerce.NotificationsModule.Core.Services;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Notifications;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Platform.Core.Common;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Core.Settings;
using VirtoCommerce.Platform.Security.Exceptions;
using VirtoCommerce.StoreModule.Core.Model;
using VirtoCommerce.StoreModule.Core.Services;
using OtpModuleSettings = VirtoCommerce.Otp.Core.ModuleConstants.Settings.General;

namespace VirtoCommerce.Otp.Data.Services;

public class OtpService(
    UserManager<ApplicationUser> userManager,
    IStoreService storeService,
    IMemberService memberService,
    INotificationSearchService notificationSearchService,
    INotificationSender notificationSender)
    : IOtpService
{
    public async Task<OtpRequestOutcome> RequestCodeAsync(string storeId, string email)
    {
        ArgumentException.ThrowIfNullOrEmpty(storeId);
        ArgumentException.ThrowIfNullOrEmpty(email);

        var store = await storeService.GetNoCloneAsync(storeId);
        if (store == null)
        {
            return OtpRequestOutcome.StoreNotFound;
        }

        if (!IsOtpSignInEnabled(store))
        {
            return OtpRequestOutcome.OtpDisabled;
        }

        ApplicationUser user;

        try
        {
            user = await userManager.FindByEmailAsync(email);
        }
        catch (DuplicateEmailException)
        {
            return OtpRequestOutcome.DuplicateEmail;
        }

        if (user == null)
        {
            return OtpRequestOutcome.UserNotFound;
        }

        if (!await userManager.GetLockoutEnabledAsync(user))
        {
            return OtpRequestOutcome.LockoutDisabled;
        }

        if (!await CanSignInToStoreAsync(user, store))
        {
            return OtpRequestOutcome.StoreAccessDenied;
        }

        var code = await userManager.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, ModuleConstants.Security.TokenPurpose);

        await SendCodeNotificationAsync(store, user, email, code);

        return OtpRequestOutcome.CodeSent;
    }

    public async Task<OtpVerifyResult> VerifyCodeAsync(string storeId, string email, string code)
    {
        ArgumentException.ThrowIfNullOrEmpty(storeId);
        ArgumentException.ThrowIfNullOrEmpty(email);
        ArgumentException.ThrowIfNullOrEmpty(code);

        var store = await storeService.GetNoCloneAsync(storeId);
        if (store == null)
        {
            return OtpVerifyResult.Fail(OtpVerifyOutcome.StoreNotFound);
        }

        if (!IsOtpSignInEnabled(store))
        {
            return OtpVerifyResult.Fail(OtpVerifyOutcome.OtpDisabled);
        }

        ApplicationUser user;

        try
        {
            user = await userManager.FindByEmailAsync(email);
        }
        catch (DuplicateEmailException)
        {
            return OtpVerifyResult.Fail(OtpVerifyOutcome.DuplicateEmail);
        }

        if (user == null)
        {
            return OtpVerifyResult.Fail(OtpVerifyOutcome.UserNotFound);
        }

        if (!await userManager.GetLockoutEnabledAsync(user))
        {
            return OtpVerifyResult.Fail(OtpVerifyOutcome.LockoutDisabled, user);
        }

        if (await userManager.IsLockedOutAsync(user))
        {
            return OtpVerifyResult.Fail(OtpVerifyOutcome.AccountLocked, user);
        }

        var isValid = await userManager.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, ModuleConstants.Security.TokenPurpose, code);
        if (!isValid)
        {
            await userManager.AccessFailedAsync(user);
            return OtpVerifyResult.Fail(OtpVerifyOutcome.InvalidCode, user);
        }

        if (!await CanSignInToStoreAsync(user, store))
        {
            return OtpVerifyResult.Fail(OtpVerifyOutcome.StoreAccessDenied, user);
        }

        await userManager.ResetAccessFailedCountAsync(user);

        return OtpVerifyResult.Succeed(user);
    }

    protected virtual async Task<bool> CanSignInToStoreAsync(ApplicationUser user, Store store)
    {
        if (user.IsAdministrator || await memberService.GetByIdAsync(user.MemberId) is not Contact)
        {
            return true;
        }

        return
            !string.IsNullOrEmpty(user.StoreId) && (
                store.Id == user.StoreId ||
                store.TrustedGroups.Contains(user.StoreId));
    }

    protected virtual async Task SendCodeNotificationAsync(Store store, ApplicationUser user, string email, string code)
    {
        var notification = await notificationSearchService.GetNotificationAsync<OtpSignInEmailNotification>(new TenantIdentity(store.Id, nameof(Store)));
        var contact = await memberService.GetByIdAsync(user.MemberId) as Contact;

        notification.To = email;
        notification.Code = code;
        notification.LanguageCode = contact?.DefaultLanguage ?? store.DefaultLanguage;

        await notificationSender.ScheduleSendNotificationAsync(notification);
    }

    protected virtual bool IsOtpSignInEnabled(Store store)
    {
        return store.Settings.GetValue<bool>(OtpModuleSettings.OtpSignInEnabled);
    }
}
