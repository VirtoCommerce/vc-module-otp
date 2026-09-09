using System;
using System.IO;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using VirtoCommerce.NotificationsModule.Core.Services;
using VirtoCommerce.NotificationsModule.TemplateLoader.FileSystem;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Core.Notifications;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Otp.Data.Services;
using VirtoCommerce.Otp.Web.RateLimiting;
using VirtoCommerce.Otp.Web.Security;
using VirtoCommerce.Platform.Core.Modularity;
using VirtoCommerce.Platform.Core.Security;
using VirtoCommerce.Platform.Core.Settings;
using VirtoCommerce.Platform.Security.ExternalSignIn;
using VirtoCommerce.StoreModule.Core.Model;

namespace VirtoCommerce.Otp.Web;

public class Module : IModule, IHasConfiguration
{
    // Client IP-based throttling for the anonymous OTP endpoints in general (a coarse defense against
    // volumetric abuse); the more targeted, per-email limiter lives in OtpService (System.Threading.RateLimiting
    // primitives are the standard, framework-native mechanism for both, not a custom OTP business feature).
    public const string IpRateLimiterPolicy = "VirtoCommerce.Otp.IpRateLimiter";

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

        serviceCollection.AddSingleton<OtpRateLimiterSettings>();

        serviceCollection.AddKeyedSingleton<PartitionedRateLimiter<string>>(OtpService.EmailRateLimiterKey, (sp, _) =>
        {
            var settings = sp.GetRequiredService<OtpRateLimiterSettings>();
            return PartitionedRateLimiter.Create<string, string>(email =>
                RateLimitPartition.GetFixedWindowLimiter(email, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 1,
                    Window = TimeSpan.FromSeconds(settings.EmailRequestCooldownSeconds),
                    QueueLimit = 0,
                }));
        });

        serviceCollection.AddRateLimiter(options => options.AddPolicy(IpRateLimiterPolicy, httpContext =>
        {
            var settings = httpContext.RequestServices.GetRequiredService<OtpRateLimiterSettings>();
            return RateLimitPartition.GetFixedWindowLimiter(
                httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = settings.IpRequestLimit,
                    Window = TimeSpan.FromSeconds(settings.IpRequestWindowSeconds),
                    QueueLimit = 0,
                });
        }));
    }

    public void PostInitialize(IApplicationBuilder appBuilder)
    {
        appBuilder.UseRateLimiter();

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
