using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using AuthorizationService.Models;

namespace AuthorizationService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;

    public AuthController(ILogger<AuthController> logger)
    {
        _logger = logger;
    }

    [HttpPost]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        await Task.CompletedTask;

        var loginAttemptCount = (HttpContext.Session.GetInt32("LoginAttemptCount") ?? 0) + 1;
        HttpContext.Session.SetInt32("LoginAttemptCount", loginAttemptCount);
        // tried too much!
        if (loginAttemptCount > 3)
        {
            return new JsonResult(new LoginResult("Failure", "To many attempts!"));
        }
        // successful attempt
        else if (model.Username == "John" && model.Password == "pwd")
        {
            HttpContext.Session.SetInt32("AttemptCount", 0);
            return new JsonResult(new LoginResult("Success", new List<Claim>
            {
                new Claim(ClaimTypes.Name, model.Username)
            }));
        }
        // unsuccessful attempt
        else
        {
            return new JsonResult(new LoginResult("Failure", $"Wrong Password!"));
        }
    }
}

