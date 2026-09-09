using System.Collections.Generic;
using VirtoCommerce.Platform.Core.Settings;

namespace VirtoCommerce.Otp.Core;

public static class ModuleConstants
{
    public static class Security
    {
        public static class Permissions
        {
            public const string Access = "otp:access";

            public static string[] AllPermissions { get; } =
            [
                Access,
            ];
        }
    }

    public static class Settings
    {
        public static class General
        {
            public static readonly SettingDescriptor Enabled = new()
            {
                Name = "OtpLogin.Enabled",
                GroupName = "OTP Sign-In|General",
                ValueType = SettingValueType.Boolean,
                DefaultValue = false,
                IsPublic = true,
            };

            public static readonly SettingDescriptor EmailRequestCooldownSeconds = new()
            {
                Name = "OtpLogin.EmailRequestCooldownSeconds",
                GroupName = "OTP Sign-In|General",
                ValueType = SettingValueType.PositiveInteger,
                DefaultValue = 15,
            };

            public static readonly SettingDescriptor IpRequestLimit = new()
            {
                Name = "OtpLogin.IpRequestLimit",
                GroupName = "OTP Sign-In|General",
                ValueType = SettingValueType.PositiveInteger,
                DefaultValue = 10,
            };

            public static readonly SettingDescriptor IpRequestWindowSeconds = new()
            {
                Name = "OtpLogin.IpRequestWindowSeconds",
                GroupName = "OTP Sign-In|General",
                ValueType = SettingValueType.PositiveInteger,
                DefaultValue = 60,
            };

            public static IEnumerable<SettingDescriptor> AllSettings
            {
                get
                {
                    yield return Enabled;
                    yield return EmailRequestCooldownSeconds;
                    yield return IpRequestLimit;
                    yield return IpRequestWindowSeconds;
                }
            }
        }

        public static IEnumerable<SettingDescriptor> StoreSettings
        {
            get
            {
                yield return General.Enabled;
            }
        }

        public static IEnumerable<SettingDescriptor> AllSettings => General.AllSettings;
    }
}
