using Microsoft.AspNetCore.Authentication;
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

        if (model.Username == "John" && model.Password == "pwd")
        {
            return new JsonResult(new LoginResult("Success", new List<Claim>
            {
                new Claim(ClaimTypes.Name, model.Username)
            }));
        }

        return new JsonResult(new LoginResult("Failure", "Wrong Password!"));
    }
}

