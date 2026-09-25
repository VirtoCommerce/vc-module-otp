using System.Threading.Tasks;
using VirtoCommerce.Otp.Core.Models;

namespace VirtoCommerce.Otp.Core.Services;

public interface IOtpService
{
    Task<OtpRequestOutcome> RequestCodeAsync(string storeId, string email);

    Task<OtpVerifyResult> VerifyCodeAsync(string storeId, string email, string code);
}
