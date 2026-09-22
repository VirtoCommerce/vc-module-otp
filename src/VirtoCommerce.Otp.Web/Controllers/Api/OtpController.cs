using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using VirtoCommerce.Otp.Core;
using VirtoCommerce.Otp.Core.Models;
using VirtoCommerce.Otp.Core.Services;
using VirtoCommerce.Platform.Core.Security;

namespace VirtoCommerce.Otp.Web.Controllers.Api;

[ApiController]
[Route("api/otp")]
[AllowAnonymous]
public class OtpController : Controller
{
    private readonly IOtpService _otpService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IHttpClientFactory _httpClientFactory;

    public OtpController(IOtpService otpService, UserManager<ApplicationUser> userManager, IHttpClientFactory httpClientFactory)
    {
        _otpService = otpService;
        _userManager = userManager;
        _httpClientFactory = httpClientFactory;
    }

    [HttpPost]
    [Route("request")]
    public async Task<ActionResult<OtpRequestResult>> RequestCode([FromBody] OtpEmailRequestCodeRequest request)
    {
        var result = await _otpService.RequestCodeAsync(request.StoreId, request.Email);

        return Ok(result);
    }

    // Adapter for Swagger's OAuth2 "password" flow (always posts username/password, can't target
    // /connect/token directly - grant_type would collide with the platform's own password grant).
    // storeId isn't part of that flow, so it's resolved from the matching user - email is unique
    // platform-wide - and the request is forwarded to /connect/token verbatim.
    [HttpPost]
    [Route("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Token([FromForm] string username, [FromForm] string password)
    {
        var user = !string.IsNullOrEmpty(username) ? await _userManager.FindByEmailAsync(username) : null;

        var formContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = ModuleConstants.Security.GrantType,
            ["storeId"] = user?.StoreId ?? string.Empty,
            ["email"] = username ?? string.Empty,
            ["code"] = password ?? string.Empty,
        });

        var httpClient = _httpClientFactory.CreateClient();
        var response = await httpClient.PostAsync($"{Request.Scheme}://{Request.Host}/connect/token", formContent);
        var content = await response.Content.ReadAsStringAsync();

        return new ContentResult
        {
            StatusCode = (int)response.StatusCode,
            Content = content,
            ContentType = "application/json",
        };
    }
}
