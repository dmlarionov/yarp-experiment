using System.Security.Claims;
using System.Text.Encodings.Web;
using Distributed.Session;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using ClaimTypes = Distributed.Session.ClaimTypes;

namespace ApiGateway;

public class AuthenticationHandler : SignInAuthenticationHandler<AuthenticationOptions>
{
    public static readonly string IpAddressClaimType = "Ip-Address";

    public static readonly string UserAgentClaimType = "User-Agent";

    private readonly ISessionStore _sessionStore;
    private readonly DistributedSessionOptions _sessionOptions;

    public AuthenticationHandler(
        IOptionsMonitor<AuthenticationOptions> options,
        ISessionStore sessionStore,
        IOptions<DistributedSessionOptions> sessionOptions,
        ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(sessionStore);
        ArgumentNullException.ThrowIfNull(sessionOptions);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(encoder);

        _sessionStore = sessionStore;
        _sessionOptions = sessionOptions.Value;
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
        {
            Response.StatusCode = 401;
            Response.ContentType = "text/plain";
            await Response.WriteAsync("Unauthorized (edge level)");
        }
    }

    /// <summary>
    /// Redirects to the access denied page.
    /// </summary>
    /// <param name="properties"></param>
    /// <returns></returns>
    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        if (!Context.Request.Path.StartsWithSegments(Options.ApiPath))
            Context.Response.Redirect(Options.AccessDeniedPath.ToString());
        else
        {
            Response.StatusCode = 403;
            Response.ContentType = "text/plain";
            await Response.WriteAsync("Forbidden (edge level)");
        }
    }

    /// <summary>
    /// Handles sign-in. Creates the authorized session and cookie.
    /// </summary>
    /// <param name="user"></param>
    /// <param name="properties"></param>
    /// <returns></returns>
    protected override async Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        await Task.CompletedTask;

        // Check if previous session present and destroy it
        if (Request.Cookies.ContainsKey(Options.CookieName))
        {
            var previousCookieValue = Request.Cookies[Options.CookieName];
            var previousTicket = Options.TicketDataFormat.Unprotect(previousCookieValue);

            if (previousTicket != null)
            {
                var previousSessionKey = previousTicket.Principal.Claims
                    .Where(x => x.Type == ClaimTypes.SessionKeyClaimType).FirstOrDefault()?.Value;

                // Here we ensure the previous session is terminated
                if (!string.IsNullOrEmpty(previousSessionKey))
                    _sessionStore.Destroy(previousSessionKey);
            }
        }

        // Take user identity
        ClaimsIdentity claimsIdentity = (ClaimsIdentity)user.Identity!;

        // If no session exists
        if (!user.HasClaim(claim => claim.Type == ClaimTypes.SessionKeyClaimType))
        {
            // Here we ensure the session is created
            // (usually this code path isn't executed since AuthorizationService does that)

            // Create a new session
            var sessionKey = SessionKeyGenerator.GetSessionKey();
            _sessionStore.Create(sessionKey, _sessionOptions.IdleTimeout, _sessionOptions.IOTimeout, true);

            // Add session key to claims
            claimsIdentity.AddClaim(new Claim(ClaimTypes.SessionKeyClaimType, sessionKey));
        }

        // Add extra protection from session fixation attack
        if (Options.CheckIpAddress && !user.HasClaim(claim => claim.Type == IpAddressClaimType))
        {
            var ipAddress = Context.Connection.RemoteIpAddress!.ToString();
            claimsIdentity.AddClaim(new Claim(IpAddressClaimType, ipAddress));
        }

        if (Options.CheckUserAgent && !user.HasClaim(claim => claim.Type == UserAgentClaimType))
        {
            var userAgent = Context.Request.Headers["User-Agent"].ToString();
            claimsIdentity.AddClaim(new Claim(UserAgentClaimType, userAgent));
        }

        // Create new ticket
        var ticket = new AuthenticationTicket(user, AuthenticationDefaults.AuthenticationScheme);
        string cookieValue = Options.TicketDataFormat.Protect(ticket);

        // Set cookie
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
            var claim = ticket.Principal.Claims.Where(x => x.Type == UserAgentClaimType).FirstOrDefault();
            if (claim == null || claim.Value != userAgent)
            {
                return AuthenticateResult.Fail("Invalid user-agent");
            }
        }

        if (Options.CheckIpAddress)
        {
            var ipAddress = Request.HttpContext.Connection.RemoteIpAddress!.ToString();
            var claim = ticket.Principal.Claims.Where(x => x.Type == IpAddressClaimType).FirstOrDefault();
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

        // Check if previous session present and destroy it
        if (Request.Cookies.ContainsKey(Options.CookieName))
        {
            var cookieValue = Request.Cookies[Options.CookieName];
            var ticket = Options.TicketDataFormat.Unprotect(cookieValue);

            if (ticket != null)
            {
                var sessionKey = ticket.Principal.Claims
                    .Where(x => x.Type == ClaimTypes.SessionKeyClaimType).FirstOrDefault()?.Value;

                // Here we ensure the session is terminated
                if (!string.IsNullOrEmpty(sessionKey))
                    _sessionStore.Destroy(sessionKey);
            }
        }

        // Delete cookie
        Response.Cookies.Delete(Options.CookieName);
    }
}
