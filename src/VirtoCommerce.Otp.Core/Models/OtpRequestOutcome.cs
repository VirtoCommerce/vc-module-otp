using System.Text.Json.Serialization;

namespace VirtoCommerce.Otp.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum OtpRequestOutcome
{
    Undefined,
    CodeSent,
    OtpDisabled,
    UserNotFound,
}
