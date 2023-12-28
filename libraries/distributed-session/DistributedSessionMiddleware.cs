// This code is originally based on ASP.NET session middleware (https://github.com/dotnet/aspnetcore/blob/main/src/Middleware/Session/src/SessionMiddleware.cs), but intentionally doesn't support session establishing (only gateway can do it).

using System;
using System.Net.Http;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Distributed.Session
{
    public class DistributedSessionMiddleware
    {
        private const int SessionKeyLength = 36; // "382c74c3-721d-4f34-80e5-57657b6cbc27"
        private readonly RequestDelegate _next;
        private readonly DistributedSessionOptions _options;
        private readonly ILogger _logger;
        private readonly ISessionStore _sessionStore;
        private readonly IDataProtector _headerProtector;

        public DistributedSessionMiddleware(
            RequestDelegate next,
            ILoggerFactory loggerFactory,
            IDataProtectionProvider dataProtectionProvider,
            ISessionStore sessionStore,
            IOptions<DistributedSessionOptions> options)
        {
            ArgumentNullException.ThrowIfNull(next);
            ArgumentNullException.ThrowIfNull(loggerFactory);
            ArgumentNullException.ThrowIfNull(dataProtectionProvider);
            ArgumentNullException.ThrowIfNull(sessionStore);
            ArgumentNullException.ThrowIfNull(options);

            _next = next;
            _logger = loggerFactory.CreateLogger<DistributedSessionMiddleware>();
            _headerProtector = dataProtectionProvider.CreateProtector(SessionDefaults.SessionHeaderProtectorPurpose);
            _options = options.Value;
            _sessionStore = sessionStore;   
        }

        /// <summary>
        /// Invokes the logic of the middleware.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns>A <see cref="Task"/> that completes when the middleware has completed processing.</returns>
        public async Task Invoke(HttpContext context)
        {
            var headerValue = context.Request.Headers[_options.PropagationHeaderName!];
            var sessionKey = SessionProtection.Unprotect(_headerProtector, headerValue, _logger);
            if (string.IsNullOrWhiteSpace(sessionKey) || sessionKey.Length != SessionKeyLength)
            {
                _logger.SessionKeyNotAvailable();

                // we have nothing to do since the key is broken
                // the session key has to be set by a gateway!
                await _next(context);
                return;
            }
            else
            {
                // create the HttpContext.Session for the current request
                var feature = new SessionFeature();
                feature.Session = _sessionStore.Create(sessionKey, _options.IdleTimeout, _options.IOTimeout, false);
                context.Features.Set<ISessionFeature>(feature);

                try
                {
                    await _next(context);
                }
                finally
                {
                    // clean up the HttpContext.Session feature
                    // (just like Microsoft does, see https://github.com/dotnet/aspnetcore/blob/main/src/Middleware/Session/src/SessionMiddleware.cs)
                    context.Features.Set<ISessionFeature?>(null);

                    // save the session data
                    if (feature.Session != null)
                    {
                        try
                        {
                            await feature.Session.CommitAsync();
                        }
                        catch (OperationCanceledException)
                        {
                            _logger.SessionCommitCanceled();
                        }
                        catch (Exception ex)
                        {
                            _logger.ErrorClosingTheSession(ex);
                        }
                    }
                }
            }
        }
    }
}

