using Microsoft.AspNetCore.DataProtection;
using Distributed.Session;

namespace ApiGateway
{
	public class DistributedSessionGatewayMiddleware
	{
        public static readonly string UnauthorizedSessionCookieName = "X-Unauthorized-Session";

        private readonly RequestDelegate _next;
        //private readonly IDataProtector _headerProtector;
        private readonly IDataProtector _cookieProtector;
        private readonly ISessionStore _sessionStore;
        private readonly ILogger _logger;

        public DistributedSessionGatewayMiddleware(
            RequestDelegate next,
            IDataProtectionProvider dataProtectionProvider,
            ISessionStore sessionStore,
            ILoggerFactory loggerFactory)
		{
            ArgumentNullException.ThrowIfNull(next);
            ArgumentNullException.ThrowIfNull(dataProtectionProvider);
            ArgumentNullException.ThrowIfNull(sessionStore);
            ArgumentNullException.ThrowIfNull(loggerFactory);

            _next = next;
            _logger = loggerFactory.CreateLogger<DistributedSessionMiddleware>();
            // The protector purpose different for cookie and header propagation
            _cookieProtector = dataProtectionProvider.CreateProtector(nameof(DistributedSessionGatewayMiddleware));
            //_headerProtector = dataProtectionProvider.CreateProtector(nameof(DistributedSessionMiddleware));
            _sessionStore = sessionStore;
        }

        public async Task Invoke(HttpContext context)
        {
            var unauthorizedSessionCookie = context.Request.Cookies[UnauthorizedSessionCookieName];
            var unauthorizedSessionKey = SessionProtection.Unprotect(_cookieProtector, unauthorizedSessionCookie);

            // for authenticated user
            if (context.User.Identity?.IsAuthenticated ?? false)
            {
                var authorizedSessionKey = context.User.Claims.Where(x => x.Type == ClaimTypes.SessionKeyClaimType).FirstOrDefault()?.Value;

                if (!string.IsNullOrWhiteSpace(authorizedSessionKey))
                {
                    // clean-up unauthorized session (if exists)
                    if (!string.IsNullOrWhiteSpace(unauthorizedSessionKey))
                    {
                        _sessionStore.Destroy(unauthorizedSessionKey);
                        context.Response.Cookies.Delete(UnauthorizedSessionCookieName);
                    }

                    // THE PROPAGATION BELOW DOESN'T WORK (please, configure HttpClient instead)
                    //// propagate authorized session in header
                    //var headerValue = SessionProtection.Protect(_headerProtector, authorizedSessionKey);
                    //// You must use the same header name you've used in distributed session options..
                    //// take attention if you've configured options via builder.Services.AddDistributedSession(options => ...)
                    //context.Request.Headers.Append(SessionDefaults.PropagationHeaderName!, headerValue);
                }
            }
            // for non-authenticated user
            else
            {
                // create unauthorized session (if doesn't exists)
                if (string.IsNullOrWhiteSpace(unauthorizedSessionKey))
                {
                    // generate new session key
                    unauthorizedSessionKey = SessionKeyGenerator.GetSessionKey();
                    var cookieValue = SessionProtection.Protect(_cookieProtector, unauthorizedSessionKey);

                    // currently, this is non-persistent cookie that wouldn't survive browser tab closed
                    CookieOptions options = new()
                    {
                        HttpOnly = true,
                        SameSite = SameSiteMode.Strict
                    };
                    context.Response.Cookies.Append(UnauthorizedSessionCookieName, cookieValue, options);
                }

                // THE PROPAGATION BELOW DOESN'T WORK (please, configure HttpClient instead)
                //// propagate unauthorized session in header
                //var headerValue = SessionProtection.Protect(_headerProtector, unauthorizedSessionKey);
                //// You must use the same header name you've used in distributed session options..
                //// take attention if you've configured options via builder.Services.AddDistributedSession(options => ...)
                //context.Request.Headers.Append(SessionDefaults.PropagationHeaderName!, headerValue);
            }

            await _next(context);

            return;
        }
	}
}

