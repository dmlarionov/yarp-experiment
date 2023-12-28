// This code is originally based on ASP.NET DistributedSessionStore (https://github.com/dotnet/aspnetcore/blob/main/src/Middleware/Session/src/DistributedSessionStore.cs), but intentionally doesn't support session establishing (only gateway can do it).

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace Distributed.Session;

/// <summary>
/// An <see cref="ISessionStore"/> backed by an <see cref="IDistributedCache"/>.
/// </summary>
public class DistributedSessionStore : ISessionStore
{
    private readonly IDistributedCache _cache;
    private readonly ILoggerFactory _loggerFactory;

    /// <summary>
    /// Initializes a new instance of <see cref="DistributedSessionStore"/>.
    /// </summary>
    /// <param name="cache">The <see cref="IDistributedCache"/> used to store the session data.</param>
    /// <param name="loggerFactory">The <see cref="ILoggerFactory"/>.</param>
    public DistributedSessionStore(IDistributedCache cache, ILoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(loggerFactory);

        _cache = cache;
        _loggerFactory = loggerFactory;
    }

    /// <inheritdoc />
    public ISession Create(string sessionKey, TimeSpan idleTimeout, TimeSpan ioTimeout, bool isNewSessionKey)
    {
        if (string.IsNullOrEmpty(sessionKey))
        {
            throw new ArgumentException(Resources.ArgumentCannotBeNullOrEmpty, nameof(sessionKey));
        }

        return new DistributedSession(_cache, sessionKey, idleTimeout, ioTimeout, _loggerFactory, isNewSessionKey);
    }

    /// <inheritdoc />
    public void Destroy(string sessionKey)
    {
        if (string.IsNullOrEmpty(sessionKey))
        {
            _cache.Remove(sessionKey);
        }
    }
}