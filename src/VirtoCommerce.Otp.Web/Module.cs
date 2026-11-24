using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using VirtoCommerce.NotificationsModule.Core.Services;
using VirtoCommerce.NotificationsModule.TemplateLoader.FileSystem;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Core.Notifications;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Otp.Data.Providers;
using VirtoCommerce.Otp.Data.Services;
using VirtoCommerce.Platform.Core.Modularity;
using VirtoCommerce.Platform.Core.Security.SignInMethods;
using VirtoCommerce.Platform.Core.Settings;
using VirtoCommerce.Platform.Security.OpenIddict;

namespace VirtoCommerce.Otp.Web;

public class Module : IModule, IHasConfiguration
{
    public ManifestModuleInfo ModuleInfo { get; set; }
    public IConfiguration Configuration { get; set; }

    public void Initialize(IServiceCollection serviceCollection)
    {
        serviceCollection.AddTransient<OtpEmailTokenProvider>();
        serviceCollection.Configure<IdentityOptions>(options =>
            options.Tokens.ProviderMap[ModuleConstants.Security.TokenProvider] = new TokenProviderDescriptor(typeof(OtpEmailTokenProvider)));

        serviceCollection.AddTransient<IOtpService, OtpService>();
        serviceCollection.AddScoped<ISignInMethodProvider, OtpSignInMethodProvider>();
        serviceCollection.AddGrantTypeHandler<OtpGrantTypeHandler>(ModuleConstants.Security.GrantType);
    }

    public void PostInitialize(IApplicationBuilder appBuilder)
    {
        var serviceProvider = appBuilder.ApplicationServices;

        var settingsRegistrar = serviceProvider.GetRequiredService<ISettingsRegistrar>();
        settingsRegistrar.RegisterSettings(ModuleConstants.Settings.AllSettings, ModuleInfo.Id);

        var notificationRegistrar = serviceProvider.GetRequiredService<INotificationRegistrar>();
        notificationRegistrar.RegisterNotification<OtpSignInEmailNotification>()
            .WithTemplatesFromPath(Path.Combine(ModuleInfo.FullPhysicalPath, "NotificationTemplates"));
    }

    public void Uninstall()
    {
        // Nothing to do here
    }
}
