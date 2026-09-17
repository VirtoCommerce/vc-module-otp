using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using VirtoCommerce.NotificationsModule.Core.Services;
using VirtoCommerce.NotificationsModule.TemplateLoader.FileSystem;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Core.Notifications;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Otp.Data.Services;
using VirtoCommerce.Otp.Data.TokenGrants;
using VirtoCommerce.Platform.Core;
using VirtoCommerce.Platform.Core.Modularity;
using VirtoCommerce.Platform.Core.Settings;
using VirtoCommerce.Platform.Security.TokenGrants;
using VirtoCommerce.StoreModule.Core.Model;

namespace VirtoCommerce.Otp.Web;

public class Module : IModule, IHasConfiguration
{
    public ManifestModuleInfo ModuleInfo { get; set; }
    public IConfiguration Configuration { get; set; }

    public void Initialize(IServiceCollection serviceCollection)
    {
        serviceCollection.AddTransient<IOtpService, OtpService>();

        serviceCollection.AddKeyedTransient<ITokenGrantHandler, EmailOtpTokenGrantHandler>(PlatformConstants.Security.GrantTypes.EmailOtpSignIn);
    }

    public void PostInitialize(IApplicationBuilder appBuilder)
    {
        var serviceProvider = appBuilder.ApplicationServices;

        var settingsRegistrar = serviceProvider.GetRequiredService<ISettingsRegistrar>();
        settingsRegistrar.RegisterSettings(ModuleConstants.Settings.AllSettings, ModuleInfo.Id);
        settingsRegistrar.RegisterSettingsForType(ModuleConstants.Settings.StoreSettings, nameof(Store));

        var notificationRegistrar = serviceProvider.GetRequiredService<INotificationRegistrar>();
        notificationRegistrar.RegisterNotification<OtpSignInEmailNotification>()
            .WithTemplatesFromPath(Path.Combine(ModuleInfo.FullPhysicalPath, "NotificationTemplates"));
    }

    public void Uninstall()
    {
        // Nothing to do here
    }
}
