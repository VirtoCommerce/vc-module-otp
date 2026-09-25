using System.Collections.Generic;
using VirtoCommerce.Platform.Core.Settings;

namespace VirtoCommerce.Otp.Core;

public static class ModuleConstants
{
    public static class Security
    {
        public const string GrantType = "otp_email";

        public static class Parameters
        {
            public const string StoreId = "storeId";
            public const string Email = "email";
            public const string Code = "code";
        }

        public static class FailureReason
        {
            public const string MissingParameter = "MissingParameter";
            public const string StoreNotFound = "StoreNotFound";
            public const string OtpDisabled = "OtpDisabled";
            public const string LockoutDisabled = "LockoutDisabled";
            public const string InvalidCode = "InvalidCode";
        }
    }

    public static class Settings
    {
        public static class General
        {
            public static readonly SettingDescriptor OtpSignInEnabled = new()
            {
                Name = "OtpSignIn.Enabled",
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
                yield return General.OtpSignInEnabled;
            }
        }

        public static IEnumerable<SettingDescriptor> AllSettings
        {
            get
            {
                yield return General.OtpSignInEnabled;
            }
        }
    }
}
