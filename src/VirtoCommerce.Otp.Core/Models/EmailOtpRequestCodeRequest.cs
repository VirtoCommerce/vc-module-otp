using System.ComponentModel.DataAnnotations;

namespace VirtoCommerce.Otp.Core.Models;

public class EmailOtpRequestCodeRequest
{
    [Required]
    public string StoreId { get; set; }

    [Required]
    [EmailAddress]
    [MaxLength(254)]
    public string Email { get; set; }
}
