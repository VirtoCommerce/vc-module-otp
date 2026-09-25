namespace VirtoCommerce.Otp.Core.Models;

public class OtpRequestResult
{
    public OtpRequestOutcome Outcome { get; set; }
    public string MaskedEmail { get; set; }
}
