using System.Threading.Tasks;
using VirtoCommerce.Otp.Core.Models;

namespace VirtoCommerce.Otp.Core.Services;

public interface IOtpService
{
    Task<OtpRequestResult> RequestCodeAsync(string email);

    Task<OtpVerifyResult> VerifyCodeAsync(string email, string code);
}
