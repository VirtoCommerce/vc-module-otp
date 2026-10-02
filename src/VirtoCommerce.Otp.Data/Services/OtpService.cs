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
    public virtual async Task<OtpResult> RequestCodeAsync(string storeId, string email)
    {
        ArgumentException.ThrowIfNullOrEmpty(storeId);
        ArgumentException.ThrowIfNullOrEmpty(email);

        var result = await ValidateUserAsync(storeId, email);
        if (result.Outcome != OtpOutcome.Success)
        {
            return result;
        }

        var store = result.Store;
        var user = result.User;

        if (!await CanSignInToStoreAsync(user, store))
        {
            return OtpResult.Fail(OtpOutcome.StoreAccessDenied, store, user);
        }

        var code = await userManager.GenerateUserTokenAsync(user, TokenOptions.DefaultEmailProvider, ModuleConstants.Security.TokenPurpose);
        await SendCodeNotificationAsync(store, user, email, code);

        return OtpResult.Succeed(store, user);
    }

    public virtual async Task<OtpResult> VerifyCodeAsync(string storeId, string email, string code)
    {
        ArgumentException.ThrowIfNullOrEmpty(storeId);
        ArgumentException.ThrowIfNullOrEmpty(email);
        ArgumentException.ThrowIfNullOrEmpty(code);

        var result = await ValidateUserAsync(storeId, email);
        if (result.Outcome != OtpOutcome.Success)
        {
            return result;
        }

        var store = result.Store;
        var user = result.User;

        var isValid = await userManager.VerifyUserTokenAsync(user, TokenOptions.DefaultEmailProvider, ModuleConstants.Security.TokenPurpose, code);
        if (!isValid)
        {
            await userManager.AccessFailedAsync(user);
            return OtpResult.Fail(OtpOutcome.InvalidCode, store, user);
        }

        if (!await CanSignInToStoreAsync(user, store))
        {
            return OtpResult.Fail(OtpOutcome.StoreAccessDenied, store, user);
        }

        await userManager.ResetAccessFailedCountAsync(user);

        return OtpResult.Succeed(store, user);
    }

    protected virtual async Task<OtpResult> ValidateUserAsync(string storeId, string email)
    {
        var store = await storeService.GetNoCloneAsync(storeId);
        if (store == null)
        {
            return OtpResult.Fail(OtpOutcome.StoreNotFound);
        }

        if (!IsOtpSignInEnabled(store))
        {
            return OtpResult.Fail(OtpOutcome.OtpDisabled, store);
        }

        ApplicationUser user;

        try
        {
            user = await userManager.FindByEmailAsync(email);
        }
        catch (DuplicateEmailException)
        {
            return OtpResult.Fail(OtpOutcome.DuplicateEmail, store);
        }

        if (user == null)
        {
            return OtpResult.Fail(OtpOutcome.UserNotFound, store);
        }

        if (!await userManager.GetLockoutEnabledAsync(user))
        {
            return OtpResult.Fail(OtpOutcome.LockoutDisabled, store, user);
        }

        if (await userManager.IsLockedOutAsync(user))
        {
            return OtpResult.Fail(OtpOutcome.AccountLocked, store, user);
        }

        return OtpResult.Succeed(store, user);
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
        var member = await memberService.GetByIdAsync(user.MemberId);

        var memberLanguage = member switch
        {
            Contact contact => contact.DefaultLanguage,
            Employee employee => employee.DefaultLanguage,
            _ => null,
        };

        notification.To = email;
        notification.Code = code;
        notification.LanguageCode = memberLanguage ?? store.DefaultLanguage;

        await notificationSender.ScheduleSendNotificationAsync(notification);
    }

    protected virtual bool IsOtpSignInEnabled(Store store)
    {
        return store.Settings.GetValue<bool>(OtpModuleSettings.OtpSignInEnabled);
    }
}
