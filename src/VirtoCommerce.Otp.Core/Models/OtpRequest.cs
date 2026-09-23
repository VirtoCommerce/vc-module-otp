using System.ComponentModel.DataAnnotations;

namespace VirtoCommerce.Otp.Core.Models;

public class OtpRequest
{
    [Required]
    [EmailAddress]
    [MaxLength(254)]
    public string Email { get; set; }
}
