using System.ComponentModel.DataAnnotations;

namespace VirtoCommerce.Otp.Core.Models;

public class EmailOtpVerifyCodeRequest
{
    [Required]
    public string StoreId { get; set; }

    [Required]
    [EmailAddress]
    [MaxLength(254)]
    public string Email { get; set; }

    [Required]
    [MaxLength(32)]
    public string Code { get; set; }
}
