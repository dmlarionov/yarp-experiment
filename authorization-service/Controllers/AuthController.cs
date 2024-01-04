using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using AuthorizationService.Models;
using Distributed.Session;
using Microsoft.Extensions.Options;
using Distributed.Permissions;
using ClaimTypes = System.Security.Claims.ClaimTypes;
using Microsoft.Extensions.Caching.Distributed;

namespace AuthorizationService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private const string LoginAttemptCountKey = "LoginAttemptCount";
    private static readonly List<User> users = new()
    {
        new User("John", "pwd",
            null,   // no extra claims
            new string[] { "Papers.Read", "Pants.Wear" }),

        new User("Bob", "power",
            new() { // extra power role claim
                new Claim(ClaimTypes.Role, "power")
            },      // extra Alcohol.Drink permission
            new string[] { "Papers.Read", "Pants.Wear", "Alcohol.Drink" })
    };
   
    private readonly ILogger<AuthController> _logger;
    private readonly ISessionStore _sessionStore;
    private readonly DistributedSessionOptions _sessionOptions;

    public AuthController(
        ISessionStore sessionStore,
        IOptions<DistributedSessionOptions> sessionOptions,
        ILogger<AuthController> logger)
    {
        ArgumentNullException.ThrowIfNull(sessionStore);
        ArgumentNullException.ThrowIfNull(sessionOptions);
        ArgumentNullException.ThrowIfNull(logger);

        _sessionStore = sessionStore;
        _sessionOptions = sessionOptions.Value;
        _logger = logger;
    }

    [HttpPost]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        await Task.CompletedTask;

        // increment attempt counter
        var loginAttemptCount = (HttpContext.Session.GetInt32(LoginAttemptCountKey) ?? 0) + 1;
        HttpContext.Session.SetInt32(LoginAttemptCountKey, loginAttemptCount);

        // tried too much!
        if (loginAttemptCount > 3)
        {
            return new JsonResult(new LoginResult("Failure", "To many attempts!"));
        }
        // yet another legal attempt
        else
        {
            var user = users.Where(u => u.Username == model.Username && u.Password == model.Password).FirstOrDefault();
            if (user != null)
            {
                // successful attempt

                // reset attempt counter (unauthorized session)
                HttpContext.Session.SetInt32(LoginAttemptCountKey, 0);

                // start a new (authorized) session
                var sessionKey = SessionKeyGenerator.GetSessionKey();
                var session = _sessionStore.Create(sessionKey, _sessionOptions.IdleTimeout, _sessionOptions.IOTimeout, true);

                if (user.Permissions != null)
                {
                    // store permissions in the session
                    session.PermissionsAppend(user.Permissions);

                    try
                    {
                        // commit session
                        await session.CommitAsync();
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogError("Committing the session was canceled.");
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError("Error closing the session. {0}", ex.Message);
                        throw;
                    }
                }

                // return success with claims
                return new JsonResult(new LoginResult("Success",
                    (user.Claims ?? new())  // the stored extra claims
                    .Append(new Claim(ClaimTypes.Name, user.Username))
                    .Append(new Claim(Distributed.Session.ClaimTypes.SessionKeyClaimType, sessionKey))));
            }
            else
            {
                // unsuccessful attempt
                var msg = (loginAttemptCount >= 3) ? "You've reached max attempts!" : "Wrong Password!";
                return new JsonResult(new LoginResult("Failure", msg));
            }
        }
    }
}

