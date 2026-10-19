using System.Linq;
using System.Threading.Tasks;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Platform.Core.Common;
using VirtoCommerce.Platform.Core.Settings;
using VirtoCommerce.StoreModule.Core.Services;
using OtpModuleSettings = VirtoCommerce.Otp.Core.ModuleConstants.Settings.General;

namespace VirtoCommerce.Otp.Data.Services;

public class OtpStoreAuthenticationTypeProvider(IStoreService storeService) : IStoreAuthenticationTypeProvider
{
    public string Name => ModuleConstants.Security.SignInType;

    public string DisplayName => ModuleConstants.Security.SignInType;

    public virtual async Task<bool> IsActiveAsync(string storeId)
    {
        var store = await storeService.GetNoCloneAsync(storeId);

        return store?.Settings.GetValue<bool>(OtpModuleSettings.OtpSignInEnabled) ?? false;
    }

    public virtual async Task SetIsActiveAsync(string storeId, bool isActive)
    {
        var store = await storeService.GetByIdAsync(storeId);
        if (store == null)
        {
            return;
        }

        var setting = store.Settings.First(x => x.Name.EqualsIgnoreCase(OtpModuleSettings.OtpSignInEnabled.Name));
        setting.Value = isActive;

        await storeService.SaveChangesAsync([store]);
    }
}
