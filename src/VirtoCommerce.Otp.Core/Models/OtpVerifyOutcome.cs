using System.Text.Json.Serialization;

namespace VirtoCommerce.Otp.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum OtpVerifyOutcome
{
    Undefined,
    Success,
    InvalidCode,
    OtpDisabled,
    AccountLocked,
}
