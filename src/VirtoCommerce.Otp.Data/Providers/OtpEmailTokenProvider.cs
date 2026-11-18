using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Platform.Core.Security;

namespace VirtoCommerce.Otp.Data.Providers;

public class OtpEmailTokenProvider : EmailTokenProvider<ApplicationUser>
{
    public override async Task<string> GetUserModifierAsync(string purpose, UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        var modifier = await base.GetUserModifierAsync(purpose, manager, user);
        var codeStamp = await manager.GetAuthenticationTokenAsync(user, ModuleConstants.Security.CodeStampLoginProvider, ModuleConstants.Security.CodeStampName);

        return $"{modifier}:{codeStamp}";
    }
}
