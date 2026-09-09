using System.ComponentModel.DataAnnotations;

namespace VirtoCommerce.Otp.Web.Models;

public class OtpRequestCodeRequest
{
    [Required]
    public string StoreId { get; set; }

    [Required]
    [EmailAddress]
    [MaxLength(254)]
    public string Email { get; set; }
}
