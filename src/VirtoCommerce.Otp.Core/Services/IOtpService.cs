using System.Threading.Tasks;
using VirtoCommerce.Otp.Core.Models;

namespace VirtoCommerce.Otp.Core.Services;

public interface IOtpService
{
    Task<OtpResult> RequestCodeAsync(string storeId, string email);

    Task<OtpResult> VerifyCodeAsync(string storeId, string email, string code);
}
