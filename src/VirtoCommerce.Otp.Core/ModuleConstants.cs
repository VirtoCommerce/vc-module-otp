using System.Collections.Generic;
using VirtoCommerce.Platform.Core.Settings;

namespace VirtoCommerce.Otp.Core;

public static class ModuleConstants
{
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
        }

        public static IEnumerable<SettingDescriptor> StoreSettings
        {
            get
            {
                yield return General.Enabled;
            }
        }

        public static IEnumerable<SettingDescriptor> AllSettings
        {
            get
            {
                yield return General.Enabled;
            }
        }
    }
}
