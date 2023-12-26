using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using ApiGateway.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace ApiGateway.Controllers
{
    public class AuthController : Controller
    {
        private readonly HttpClient _authServiceClient;
        private readonly ILogger<AuthController> _logger;
        private readonly JsonSerializerOptions _jsonSerializerOptions;

        public AuthController(IHttpClientFactory httpClientFactory, ILogger<AuthController> logger)
        {
            _authServiceClient = httpClientFactory.CreateClient("Auth-Service-Client");
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
                LoginResult? result;
                HttpResponseMessage response = await _authServiceClient.PostAsJsonAsync<LoginModel>("/auth", model);
                response.EnsureSuccessStatusCode();
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
    }
}

