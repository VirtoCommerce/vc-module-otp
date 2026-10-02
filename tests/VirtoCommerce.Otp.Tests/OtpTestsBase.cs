using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using VirtoCommerce.CustomerModule.Core.Model;
using VirtoCommerce.CustomerModule.Core.Services;
using VirtoCommerce.NotificationsModule.Core.Model;
using VirtoCommerce.NotificationsModule.Core.Services;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Core.Notifications;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Otp.Data.Services;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Security.Exceptions;
using VirtoCommerce.StoreModule.Core.Model;
using VirtoCommerce.StoreModule.Core.Services;
using OtpModuleSettings = VirtoCommerce.Otp.Core.ModuleConstants.Settings.General;

namespace VirtoCommerce.Otp.Tests;

public abstract class OtpTestsBase
{
    public const string StoreId = "test-store";
    public const string OtpDisabledStoreId = "otp-disabled-store";
    public const string UnknownStoreId = "unknown-store";
    public const string TrustedStoreId = "trusted-store";
    public const string UntrustedStoreId = "untrusted-store";
    public const string ContactId = "contact-1";
    public const string EmployeeId = "employee-1";
    public const string NoLanguageContactId = "contact-without-language";
    public const string StoreLanguage = "en-US";
    public const string ContactLanguage = "de-DE";
    public const string EmployeeLanguage = "fr-FR";

    public const string ActiveUserEmail = "active@acme.com";
    public const string TemporarilyLockedUserEmail = "temporarily-locked@acme.com";
    public const string PermanentlyLockedUserEmail = "permanently-locked@acme.com";
    public const string LockoutDisabledUserEmail = "lockout-disabled@acme.com";
    public const string UntrustedStoreUserEmail = "untrusted-store@acme.com";
    public const string UnconfirmedEmailUserEmail = "unconfirmed-email@acme.com";
    public const string TrustedStoreUserEmail = "trusted-store@acme.com";
    public const string NoStoreUserEmail = "no-store@acme.com";
    public const string AdministratorUserEmail = "administrator@acme.com";
    public const string EmployeeUserEmail = "employee@acme.com";
    public const string NoLanguageUserEmail = "no-language@acme.com";
    public const string DuplicateEmail = "duplicate@acme.com";
    public const string UnknownEmail = "unknown@acme.com";

    public const string ActiveUserId = "active-user";
    public const string TemporarilyLockedUserId = "temporarily-locked-user";
    public const string PermanentlyLockedUserId = "permanently-locked-user";
    public const string LockoutDisabledUserId = "lockout-disabled-user";
    public const string UntrustedStoreUserId = "untrusted-store-user";
    public const string UnconfirmedEmailUserId = "unconfirmed-email-user";
    public const string TrustedStoreUserId = "trusted-store-user";
    public const string NoStoreUserId = "no-store-user";
    public const string AdministratorUserId = "administrator-user";
    public const string EmployeeUserId = "employee-user";
    public const string NoLanguageUserId = "no-language-user";
    public const string FirstDuplicateUserId = "first-duplicate-user";
    public const string SecondDuplicateUserId = "second-duplicate-user";

    public const string ValidCode = "246810";
    public const string InvalidCode = "000000";
    public const int LockoutSeconds = 600;

    public IOtpService OtpService { get; }

    public Mock<UserManager<ApplicationUser>> UserManager { get; }

    public Mock<SignInManager<ApplicationUser>> SignInManager { get; }

    public IOptions<IdentityOptions> IdentityOptions { get; } = Options.Create(new IdentityOptions());

    public Mock<IStoreService> StoreService { get; }

    public Mock<INotificationSender> NotificationSender { get; }

    public ApplicationUser ActiveUser { get; }

    public ApplicationUser TemporarilyLockedUser { get; }

    public ApplicationUser PermanentlyLockedUser { get; }

    public ApplicationUser LockoutDisabledUser { get; }

    public ApplicationUser UntrustedStoreUser { get; }

    public ApplicationUser UnconfirmedEmailUser { get; }

    public ApplicationUser TrustedStoreUser { get; }

    public ApplicationUser NoStoreUser { get; }

    public ApplicationUser AdministratorUser { get; }

    public ApplicationUser EmployeeUser { get; }

    public ApplicationUser NoLanguageUser { get; }

    protected OtpTestsBase()
    {
        var store = new Store
        {
            Id = StoreId,
            DefaultLanguage = StoreLanguage,
            TrustedGroups = [TrustedStoreId],
            Settings =
            [
                new() { Name = OtpModuleSettings.OtpSignInEnabled.Name, Value = true },
            ],
        };

        var disabledStore = new Store
        {
            Id = OtpDisabledStoreId,
            Settings =
            [
                new() { Name = OtpModuleSettings.OtpSignInEnabled.Name, Value = false },
            ],
        };

        var stores = new[] { store, disabledStore };
        StoreService = new Mock<IStoreService>();

        StoreService
            .Setup(x => x.GetAsync(It.IsAny<IList<string>>(), null, false))
            .ReturnsAsync((IList<string> ids, string _, bool _) => stores.Where(x => ids.Contains(x.Id)).ToList());

        var members = new Member[]
        {
            new Contact { Id = ContactId, DefaultLanguage = ContactLanguage },
            new Employee { Id = EmployeeId, DefaultLanguage = EmployeeLanguage },
            new Contact { Id = NoLanguageContactId },
        };

        var memberService = new Mock<IMemberService>();

        memberService
            .Setup(x => x.GetByIdAsync(It.IsAny<string>(), null, null))
            .ReturnsAsync((string id, string _, string _) => members.FirstOrDefault(x => x.Id == id));

        ActiveUser = CreateUser(ActiveUserId, ActiveUserEmail, StoreId);
        TemporarilyLockedUser = CreateUser(TemporarilyLockedUserId, TemporarilyLockedUserEmail, StoreId, DateTimeOffset.UtcNow.AddSeconds(LockoutSeconds));
        PermanentlyLockedUser = CreateUser(PermanentlyLockedUserId, PermanentlyLockedUserEmail, StoreId, DateTime.MaxValue.ToUniversalTime());
        LockoutDisabledUser = CreateUser(LockoutDisabledUserId, LockoutDisabledUserEmail, StoreId, lockoutEnabled: false);
        UntrustedStoreUser = CreateUser(UntrustedStoreUserId, UntrustedStoreUserEmail, UntrustedStoreId);
        UnconfirmedEmailUser = CreateUser(UnconfirmedEmailUserId, UnconfirmedEmailUserEmail, StoreId, emailConfirmed: false);
        TrustedStoreUser = CreateUser(TrustedStoreUserId, TrustedStoreUserEmail, TrustedStoreId);
        NoStoreUser = CreateUser(NoStoreUserId, NoStoreUserEmail, storeId: null);
        AdministratorUser = CreateUser(AdministratorUserId, AdministratorUserEmail, UntrustedStoreId, isAdministrator: true);
        EmployeeUser = CreateUser(EmployeeUserId, EmployeeUserEmail, UntrustedStoreId, memberId: EmployeeId);
        NoLanguageUser = CreateUser(NoLanguageUserId, NoLanguageUserEmail, StoreId, memberId: NoLanguageContactId);

        var users = new[]
        {
            ActiveUser,
            TemporarilyLockedUser,
            PermanentlyLockedUser,
            LockoutDisabledUser,
            UntrustedStoreUser,
            UnconfirmedEmailUser,
            TrustedStoreUser,
            NoStoreUser,
            AdministratorUser,
            EmployeeUser,
            NoLanguageUser,
            CreateUser(FirstDuplicateUserId, DuplicateEmail, StoreId),
            CreateUser(SecondDuplicateUserId, DuplicateEmail, StoreId),
        };

        var userStore = new Mock<IUserStore<ApplicationUser>>();
        UserManager = new Mock<UserManager<ApplicationUser>>(userStore.Object, null, null, null, null, null, null, null, null);

        UserManager
            .Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
            .Returns((string email) =>
            {
                var matches = users.Where(x => x.Email == email).ToList();

                return matches.Count > 1
                    ? Task.FromException<ApplicationUser>(new DuplicateEmailException(email))
                    : Task.FromResult(matches.SingleOrDefault());
            });

        UserManager
            .Setup(x => x.GetLockoutEnabledAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync((ApplicationUser user) => user.LockoutEnabled);

        UserManager
            .Setup(x => x.IsLockedOutAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync((ApplicationUser user) => user.LockoutEnd > DateTimeOffset.UtcNow);

        UserManager
            .Setup(x => x.VerifyUserTokenAsync(It.IsAny<ApplicationUser>(), TokenOptions.DefaultEmailProvider, ModuleConstants.Security.TokenPurpose, It.IsAny<string>()))
            .ReturnsAsync((ApplicationUser _, string _, string _, string code) => code == ValidCode);

        SignInManager = new Mock<SignInManager<ApplicationUser>>(
            UserManager.Object,
            new Mock<IHttpContextAccessor>().Object,
            new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>().Object,
            IdentityOptions,
            new Mock<ILogger<SignInManager<ApplicationUser>>>().Object,
            new Mock<IAuthenticationSchemeProvider>().Object,
            new Mock<IUserConfirmation<ApplicationUser>>().Object);

        SignInManager.Object.UserManager = UserManager.Object;

        SignInManager
            .Setup(x => x.CanSignInAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync((ApplicationUser user) => user.EmailConfirmed);

        SignInManager
            .Setup(x => x.CreateUserPrincipalAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity()));

        var notificationSearchService = new Mock<INotificationSearchService>();

        notificationSearchService
            .Setup(x => x.SearchNotificationsAsync(It.IsAny<NotificationSearchCriteria>()))
            .ReturnsAsync(new NotificationSearchResult { Results = [new OtpSignInEmailNotification()] });

        NotificationSender = new Mock<INotificationSender>();

        OtpService = new OtpService(
            UserManager.Object,
            StoreService.Object,
            memberService.Object,
            notificationSearchService.Object,
            NotificationSender.Object);
    }

    private static ApplicationUser CreateUser(string id, string email, string storeId, DateTimeOffset? lockoutEnd = null, bool lockoutEnabled = true, bool emailConfirmed = true, string memberId = ContactId, bool isAdministrator = false)
    {
        return new ApplicationUser
        {
            Id = id,
            Email = email,
            MemberId = memberId,
            StoreId = storeId,
            LockoutEnd = lockoutEnd,
            LockoutEnabled = lockoutEnabled,
            EmailConfirmed = emailConfirmed,
            IsAdministrator = isAdministrator,
        };
    }
}
