using System;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;

namespace Distributed.Authentication
{
    public class AuthenticationHandler : AuthenticationHandler<AuthenticationOptions>
    {
        private readonly TicketSerializer _ticketSerializer = new TicketSerializer();
        private readonly IDataProtector _protector;

        public AuthenticationHandler(
            IDataProtectionProvider dataProtectionProvider,
            IOptionsMonitor<AuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
            _protector = dataProtectionProvider.CreateProtector("ticket");
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = 401;
            Response.ContentType = "text/plain";
            await Response.WriteAsync("Unauthorized (service level)");
        }

        protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = 403;
            Response.ContentType = "text/plain";
            await Response.WriteAsync("Forbidden (service level)");
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            await Task.CompletedTask;

            StringValues header;
            if (!Request.Headers.TryGetValue(HeaderNames.Authorization, out header))
                return AuthenticateResult.NoResult();

            string authorization = header.ToString();

            if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var token = authorization.Substring("Bearer ".Length).Trim();
                if (!string.IsNullOrEmpty(token))
                {
                    var ticket = _ticketSerializer.Deserialize(TicketProtection.Unprotect(_protector, token));

                    if (ticket == null)
                    {
                        return AuthenticateResult.Fail("Invalid content");
                    }

                    return AuthenticateResult.Success(ticket);
                }
            }

            // If no token found, no further work possible
            return AuthenticateResult.NoResult();
        }
    }
}

