using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using ApiGateway.Models;
using Distributed.Session;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace ApiGateway.Controllers
{
    public class AuthController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<AuthController> _logger;
        private readonly JsonSerializerOptions _jsonSerializerOptions;
        private readonly IDataProtector _headerProtector;
        private readonly IDataProtector _cookieProtector;
        private readonly IConfiguration _configuration;

        public AuthController(
            IHttpClientFactory httpClientFactory,
            IDataProtectionProvider dataProtectionProvider,
            IConfiguration configuration,
            ILogger<AuthController> logger)
        {
            ArgumentNullException.ThrowIfNull(httpClientFactory);
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentNullException.ThrowIfNull(dataProtectionProvider);
            ArgumentNullException.ThrowIfNull(logger);

            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
            //_authServiceClient = httpClientFactory.CreateClient("Auth-Service-Client");
            _cookieProtector = dataProtectionProvider.CreateProtector(nameof(DistributedSessionGatewayMiddleware));
            _headerProtector = dataProtectionProvider.CreateProtector(nameof(DistributedSessionMiddleware));
            _logger = logger;
            _jsonSerializerOptions = new JsonSerializerOptions();
            _jsonSerializerOptions.Converters.Add(new ClaimConverter());
            _jsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        }

        [HttpGet]
        public IActionResult Login()
        {
            var model = new LoginPageModel();
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login([FromForm] LoginModel model)
        {
            try
            {
                var client = _httpClientFactory.CreateClient("Auth-Service-Client");
                AppendSessionHeaders(client.DefaultRequestHeaders);
                HttpResponseMessage response = await client.PostAsJsonAsync<LoginModel>("/auth", model);
                response.EnsureSuccessStatusCode();

                LoginResult? result;
                result = await response.Content.ReadFromJsonAsync<LoginResult>(_jsonSerializerOptions);

                // Unsuccessful login
                if (result == null || result.Code != "Success")
                    return View(new LoginPageModel(result?.Explanation ?? string.Empty, model));

                // Successful login
                var claimsIdentity = new ClaimsIdentity(result.Claims, AuthenticationDefaults.AuthenticationScheme);

                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                await HttpContext.SignInAsync(claimsPrincipal);

                return Redirect("/");
            }
            catch (Exception e)
            {
                _logger.LogError("Exception during login attempt: {e}", e.Message);
                return View(new LoginPageModel("Something went wrong! Please, try again.", model));
            }
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return Redirect("/");
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        // TODO: Move this session propagation from controller to HttpClient configuration
        private void AppendSessionHeaders (HttpRequestHeaders headers)
        {
            // for authenticated user
            if (HttpContext.User.Identity?.IsAuthenticated ?? false)
            {
                var authorizedSessionKey = HttpContext.User.Claims.Where(x => x.Type == AuthenticationHandler.SessionKeyClaimType).FirstOrDefault()?.Value;

                if (!string.IsNullOrWhiteSpace(authorizedSessionKey))
                {
                    // propagate authorized session in header
                    var headerValue = SessionProtection.Protect(_headerProtector, authorizedSessionKey);
                    // You must use the same header name you've used in distributed session options..
                    // take attention if you've configured options via builder.Services.AddDistributedSession(options => ...)
                    headers.Add(SessionDefaults.PropagationHeaderName!, headerValue);
                }
            }
            // for non-authenticated user
            else
            {
                var cookieValue = HttpContext.Request.Cookies[DistributedSessionGatewayMiddleware.UnauthorizedSessionCookieName];
                var unauthorizedSessionKey = SessionProtection.Unprotect(_cookieProtector, cookieValue);

                if (!string.IsNullOrWhiteSpace(unauthorizedSessionKey))
                {
                    // propagate unauthorized session in header
                    var headerValue = SessionProtection.Protect(_headerProtector, unauthorizedSessionKey);
                    // You must use the same header name you've used in distributed session options..
                    // take attention if you've configured options via builder.Services.AddDistributedSession(options => ...)
                    headers.Add(SessionDefaults.PropagationHeaderName!, headerValue);
                }
            }
        }
    }
}

