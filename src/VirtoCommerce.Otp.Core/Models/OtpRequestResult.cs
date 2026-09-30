using Microsoft.AspNetCore.Identity;

namespace VirtoCommerce.Otp.Core.Models;

public class OtpRequestResult
{
    public bool Succeeded => Error is null;
    public IdentityError Error { get; set; }
    public string MaskedEmail { get; set; }
}
