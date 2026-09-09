using System.Text.Json.Serialization;

namespace VirtoCommerce.Otp.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum OtpRequestOutcome
{
    Sent,
    Disabled,
}

public class OtpRequestResult
{
    public OtpRequestOutcome Outcome { get; set; }
    public string MaskedEmail { get; set; }
}
