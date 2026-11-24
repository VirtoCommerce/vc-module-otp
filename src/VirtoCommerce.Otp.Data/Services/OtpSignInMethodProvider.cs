using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using VirtoCommerce.Platform.Core.Common;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Core.Security.SignInMethods;
using VirtoCommerce.Platform.Core.Settings;
using VirtoCommerce.Platform.Security;
using static VirtoCommerce.Otp.Core.ModuleConstants.Security;
using OtpModuleSettings = VirtoCommerce.Otp.Core.ModuleConstants.Settings.General;

namespace VirtoCommerce.Otp.Data.Services;

public class OtpSignInMethodProvider(ISettingsManager settingsManager) : ISignInMethodProvider
{
    public virtual async Task<IList<SignInMethod>> GetSignInMethodsAsync(ApplicationUser user = null)
    {
        // OTP has no per-user keys, so it is not listed among a user's own sign-in methods.
        if (user != null ||
            !await settingsManager.GetValueAsync<bool>(OtpModuleSettings.OtpSignInEnabled))
        {
            return [];
        }

        var signInMethod = AbstractTypeFactory<SignInMethod>.TryCreateInstance();

        signInMethod.Kind = SignInType;
        signInMethod.Name = SignInType;
        signInMethod.DisplayName = SignInType;

        return [signInMethod];
    }

    public virtual Task<IdentityResult> RenameKeyAsync(ApplicationUser user, string signInMethodName, string keyId, string name)
    {
        return Task.FromResult(IdentityResult.Failed(CommonErrorDescriber.OperationNotSupported()));
    }

    public virtual Task<IdentityResult> DeleteKeyAsync(ApplicationUser user, string signInMethodName, string keyId)
    {
        return Task.FromResult(IdentityResult.Failed(CommonErrorDescriber.OperationNotSupported()));
    }
}
