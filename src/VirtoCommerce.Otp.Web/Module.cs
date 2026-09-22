using System;
using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi;
using Swashbuckle.AspNetCore.Filters;
using Swashbuckle.AspNetCore.SwaggerGen;
using VirtoCommerce.NotificationsModule.Core.Services;
using VirtoCommerce.NotificationsModule.TemplateLoader.FileSystem;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Core.Notifications;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Otp.Data.Services;
using VirtoCommerce.Otp.Data.TokenGrants;
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

        serviceCollection.AddTransient<ITokenGrantHandler, OtpEmailTokenGrantHandler>();

        serviceCollection.AddOpenIddict().AddServer(serverBuilder => serverBuilder.AllowCustomFlow(ModuleConstants.Security.GrantType));

        serviceCollection.AddHttpClient();

        AddOtpSecurityScheme(serviceCollection);
    }

    // Swagger's Authorize popup only drives the standard OAuth2 flows, not a custom grant type -
    // its Password flow fits the "submit two values, get a token" shape if pointed at a dedicated
    // endpoint instead of /connect/token directly. See OtpController.Token for that adapter.
    private static void AddOtpSecurityScheme(IServiceCollection serviceCollection)
    {
        serviceCollection.Configure<SwaggerGenOptions>(options =>
        {
            options.AddSecurityDefinition(ModuleConstants.Security.GrantType, new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.OAuth2,
                Description = "OTP sign-in: request a code via POST /api/otp/request first, then Authorize here with the email as \"username\" and the code as \"password\".",
                Flows = new OpenApiOAuthFlows
                {
                    Password = new OpenApiOAuthFlow
                    {
                        TokenUrl = new Uri("/api/otp/token", UriKind.Relative),
                    },
                },
            });

            options.OperationFilter<SecurityRequirementsOperationFilter>(true, ModuleConstants.Security.GrantType);
        });
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
