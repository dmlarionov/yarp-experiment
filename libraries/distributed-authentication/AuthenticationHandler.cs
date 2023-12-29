﻿using System;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Distributed.Authentication
{
    public class AuthenticationHandler : AuthenticationHandler<AuthenticationOptions>
    {
        private readonly ISecureDataFormat<AuthenticationTicket> _ticketDataFormat;

        public AuthenticationHandler(
            //IDataProtector dataProtector,
            IOptionsMonitor<AuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
            //var protector = DataProtectionProvider.Create(Options.ApplicationName).CreateProtector("ticket");
            //var protector = dataProtector.CreateProtector("ticket");
            // TODO: Remove hard-coded "yarn-experiment" as application name.
            var protector = DataProtectionProvider.Create("yarn-experiment").CreateProtector("ticket");
            _ticketDataFormat = new SecureDataFormat<AuthenticationTicket>(new TicketSerializer(), protector);
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            await Task.CompletedTask;
            Response.StatusCode = 401;
        }

        protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            await Task.CompletedTask;
            Response.StatusCode = 403;
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
                    var ticket = _ticketDataFormat.Unprotect(token);

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
