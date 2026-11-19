using System;
using System.Linq;
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
using VirtoCommerce.Platform.Core.DistributedLock;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Security.Caching;
using VirtoCommerce.Platform.Security.Exceptions;
using VirtoCommerce.StoreModule.Core.Model;
using VirtoCommerce.StoreModule.Core.Services;

namespace VirtoCommerce.Otp.Data.Services;

public class OtpService(
    UserManager<ApplicationUser> userManager,
    IStoreService storeService,
    IStoreAuthenticationService storeAuthenticationService,
    IMemberService memberService,
    INotificationSearchService notificationSearchService,
    INotificationSender notificationSender,
    IDistributedLock distributedLock)
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

        var code = await userManager.GenerateUserTokenAsync(user, ModuleConstants.Security.TokenProvider, ModuleConstants.Security.TokenPurpose);
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

        return await distributedLock.ExecuteAsync(GetCodeLockResource(result.User),
            _ => VerifyAndConsumeCodeAsync(result.Store, result.User, code));
    }

    protected virtual async Task<OtpResult> VerifyAndConsumeCodeAsync(Store store, ApplicationUser user, string code)
    {
        var currentUser = await ReloadUserAsync(user);
        if (currentUser == null)
        {
            return OtpResult.Fail(OtpOutcome.UserNotFound, store);
        }

        if (await userManager.IsLockedOutAsync(currentUser))
        {
            return OtpResult.Fail(OtpOutcome.AccountLocked, store, currentUser);
        }

        var isValid = await userManager.VerifyUserTokenAsync(currentUser, ModuleConstants.Security.TokenProvider, ModuleConstants.Security.TokenPurpose, code);
        if (!isValid)
        {
            await userManager.AccessFailedAsync(currentUser);
            return OtpResult.Fail(OtpOutcome.InvalidCode, store, currentUser);
        }

        if (!await CanSignInToStoreAsync(currentUser, store))
        {
            return OtpResult.Fail(OtpOutcome.StoreAccessDenied, store, currentUser);
        }

        if (!await UpdateCodeStampAsync(currentUser))
        {
            return OtpResult.Fail(OtpOutcome.CodeStampNotUpdated, store, currentUser);
        }

        await userManager.ResetAccessFailedCountAsync(currentUser);

        return OtpResult.Succeed(store, currentUser);
    }

    protected virtual Task<ApplicationUser> ReloadUserAsync(ApplicationUser user)
    {
        SecurityCacheRegion.ExpireUser(user);

        return userManager.FindByIdAsync(user.Id);
    }

    protected virtual async Task<OtpResult> ValidateUserAsync(string storeId, string email)
    {
        var store = await storeService.GetNoCloneAsync(storeId);
        if (store == null)
        {
            return OtpResult.Fail(OtpOutcome.StoreNotFound);
        }

        if (!await IsOtpSignInEnabledAsync(store))
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

    protected virtual string GetCodeLockResource(ApplicationUser user)
    {
        return $"{ModuleConstants.Security.CodeLockResourcePrefix}:{user.Id}";
    }

    protected virtual async Task<bool> UpdateCodeStampAsync(ApplicationUser user)
    {
        try
        {
            var result = await userManager.SetAuthenticationTokenAsync(user,
                ModuleConstants.Security.CodeStampLoginProvider, ModuleConstants.Security.CodeStampName, Guid.NewGuid().ToString("N"));

            return result.Succeeded;
        }
        catch (DuplicateEmailException)
        {
            return false;
        }
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

    protected virtual async Task<bool> IsOtpSignInEnabledAsync(Store store)
    {
        var schemes = await storeAuthenticationService.GetStoreSchemesAsync(store.Id, clone: false);

        return schemes.Any(x => x.Name.EqualsIgnoreCase(ModuleConstants.Security.SignInType) && x.IsActive);
    }
}
