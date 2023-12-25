using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace ApiGateway;

public class AuthenticationHandler : SignInAuthenticationHandler<AuthenticationOptions>
{
    public AuthenticationHandler(IOptionsMonitor<AuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    /// <summary>
    /// Redirects to the login page.
    /// </summary>
    /// <param name="properties"></param>
    /// <returns></returns>
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        await Task.CompletedTask;

        if (!Context.Request.Path.StartsWithSegments(Options.ApiPath))
            Context.Response.Redirect(Options.LoginPath.ToString());
        else
            Response.StatusCode = 401;
    }

    /// <summary>
    /// Redirects to the access denied page.
    /// </summary>
    /// <param name="properties"></param>
    /// <returns></returns>
    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        await Task.CompletedTask;

        if (!Context.Request.Path.StartsWithSegments(Options.ApiPath))
            Context.Response.Redirect(Options.AccessDeniedPath.ToString());
        else
            Response.StatusCode = 403;
    }

    /// <summary>
    /// Handles sign-in. Creates the cookie.
    /// </summary>
    /// <param name="user"></param>
    /// <param name="properties"></param>
    /// <returns></returns>
    protected override async Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        await Task.CompletedTask;

        ClaimsIdentity claimsIdentity = (ClaimsIdentity)user.Identity!;
        if (Options.CheckIpAddress && !user.HasClaim(claim => claim.Type == "IpAddress"))
        {
            var ipAddress = Context.Connection.RemoteIpAddress!.ToString();
            claimsIdentity.AddClaim(new Claim("IpAddress", ipAddress));
        }

        if (Options.CheckUserAgent && !user.HasClaim(claim => claim.Type == "UserAgent"))
        {
            var userAgent = Context.Request.Headers["User-Agent"].ToString();
            claimsIdentity.AddClaim(new Claim("UserAgent", userAgent));
        }

        user.AddIdentity(claimsIdentity);

        var ticket = new AuthenticationTicket(user, AuthenticationDefaults.AuthenticationScheme);
        string cookieValue = Options.TicketDataFormat.Protect(ticket);

        CookieOptions options = new()
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.Add(Options.ExpireTimeSpan),
            SameSite = SameSiteMode.Strict
        };

        Response.Cookies.Append(Options.CookieName, cookieValue, options);
    }

    /// <summary>
    /// Extracts the session cookie information and checks validity.
    /// </summary>
    /// <returns></returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        await Task.CompletedTask;
        if (!Request.Cookies.ContainsKey(Options.CookieName)) return AuthenticateResult.NoResult();

        var cookieValue = Request.Cookies[Options.CookieName];
        var ticket = Options.TicketDataFormat.Unprotect(cookieValue);

        if (ticket == null)
        {
            return AuthenticateResult.Fail("Invalid content");
        }

        if (Options.CheckUserAgent)
        {
            var userAgent = Request.Headers["User-Agent"].ToString();
            var claim = ticket.Principal.Claims.Where(x => x.Type == "UserAgent").FirstOrDefault();
            if (claim == null || claim.Value != userAgent)
            {
                return AuthenticateResult.Fail("Invalid user-agent");
            }
        }

        if (Options.CheckIpAddress)
        {
            var ipAddress = Request.HttpContext.Connection.RemoteIpAddress!.ToString();
            var claim = ticket.Principal.Claims.Where(x => x.Type == "IpAddress").FirstOrDefault();
            if (claim == null || claim.Value != ipAddress)
            {
                return AuthenticateResult.Fail("Invalid ip-address");
            }
        }

        return AuthenticateResult.Success(ticket);
    }

    /// <summary>
    /// Handles sing-out. Removes the cookie.
    /// </summary>
    /// <param name="properties"></param>
    /// <returns></returns>
    protected override async Task HandleSignOutAsync(AuthenticationProperties? properties)
    {
        await Task.CompletedTask;

        Response.Cookies.Delete(Options.CookieName);
    }
}
