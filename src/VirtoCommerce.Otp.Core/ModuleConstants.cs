namespace VirtoCommerce.Otp.Core;

public static class ModuleConstants
{
    public static class Security
    {
        public static class Permissions
        {
            public const string Create = "otp:create";
            public const string Read = "otp:read";
            public const string Update = "otp:update";
            public const string Delete = "otp:delete";

            public static string[] AllPermissions { get; } =
            [
                Create,
                Read,
                Update,
                Delete,
            ];
        }
    }
}
