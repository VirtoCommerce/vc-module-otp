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
using VirtoCommerce.Otp.Web.Security;
using VirtoCommerce.Platform.Core.Modularity;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Core.Settings;
using VirtoCommerce.Platform.Security.ExternalSignIn;
using VirtoCommerce.StoreModule.Core.Model;

namespace VirtoCommerce.Otp.Web;

public class Module : IModule, IHasConfiguration
{
    public ManifestModuleInfo ModuleInfo { get; set; }
    public IConfiguration Configuration { get; set; }

    public void Initialize(IServiceCollection serviceCollection)
    {
        serviceCollection.AddTransient<IOtpService, OtpService>();

        serviceCollection.AddSingleton<OtpExternalSignInProvider>();
        serviceCollection.AddSingleton(provider => new ExternalSignInProviderConfiguration
        {
            AuthenticationType = OtpExternalSignInProvider.AuthenticationType,
            Provider = provider.GetRequiredService<OtpExternalSignInProvider>(),
        });
        serviceCollection.AddTransient<OtpExternalSignInService>();
    }

    public void PostInitialize(IApplicationBuilder appBuilder)
    {
        var serviceProvider = appBuilder.ApplicationServices;

        var settingsRegistrar = serviceProvider.GetRequiredService<ISettingsRegistrar>();
        settingsRegistrar.RegisterSettings(ModuleConstants.Settings.AllSettings, ModuleInfo.Id);
        settingsRegistrar.RegisterSettingsForType(ModuleConstants.Settings.StoreSettings, nameof(Store));

        var permissionsRegistrar = serviceProvider.GetRequiredService<IPermissionsRegistrar>();
        permissionsRegistrar.RegisterPermissions(ModuleInfo.Id, "Otp", ModuleConstants.Security.Permissions.AllPermissions);

        var notificationRegistrar = serviceProvider.GetRequiredService<INotificationRegistrar>();
        notificationRegistrar.RegisterNotification<OtpSignInEmailNotification>()
            .WithTemplatesFromPath(Path.Combine(ModuleInfo.FullPhysicalPath, "NotificationTemplates"));
    }

    public void Uninstall()
    {
        // Nothing to do here
    }
}
