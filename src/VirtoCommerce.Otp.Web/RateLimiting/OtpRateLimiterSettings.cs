using VirtoCommerce.Platform.Core.Settings;
using ModuleSettings = VirtoCommerce.Otp.Core.ModuleConstants.Settings.General;

namespace VirtoCommerce.Otp.Web.RateLimiting;

/// <summary>
/// Reads the module's rate-limiter settings once (blocking) on first resolution and caches them for the
/// process lifetime: the rate limiter partition factories run per request/per partition and cannot await,
/// so a single synchronous read here — resolved lazily by the DI container as a singleton — avoids hitting
/// the settings store on every request. A settings change therefore requires an app restart to take effect.
/// </summary>
public class OtpRateLimiterSettings
{
    public int EmailRequestCooldownSeconds { get; }
    public int IpRequestLimit { get; }
    public int IpRequestWindowSeconds { get; }

    public OtpRateLimiterSettings(ISettingsManager settingsManager)
    {
        EmailRequestCooldownSeconds = settingsManager.GetValue<int>(ModuleSettings.EmailRequestCooldownSeconds);
        IpRequestLimit = settingsManager.GetValue<int>(ModuleSettings.IpRequestLimit);
        IpRequestWindowSeconds = settingsManager.GetValue<int>(ModuleSettings.IpRequestWindowSeconds);
    }
}
