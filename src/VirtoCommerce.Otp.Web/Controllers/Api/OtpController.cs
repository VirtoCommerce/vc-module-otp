using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;

namespace VirtoCommerce.Otp.Web.Controllers.Api;

[ApiController]
[Route("api/otp")]
[AllowAnonymous]
public class OtpController : Controller
{
    private readonly IOtpService _otpService;

    public OtpController(IOtpService otpService)
    {
        _otpService = otpService;
    }

    [HttpPost]
    [Route("request")]
    public async Task<ActionResult<OtpRequestResult>> RequestCode([FromBody] OtpRequest request)
    {
        var result = await _otpService.RequestCodeAsync(request.StoreId, request.Email);

        return Ok(result);
    }
}
