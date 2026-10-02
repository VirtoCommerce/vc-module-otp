using VirtoCommerce.NotificationsModule.Core.Model;

namespace VirtoCommerce.Otp.Core.Notifications;

public class OtpSignInEmailNotification : EmailNotification
{
    public OtpSignInEmailNotification()
        : base(nameof(OtpSignInEmailNotification))
    {
    }

    public string Code { get; set; }
}
