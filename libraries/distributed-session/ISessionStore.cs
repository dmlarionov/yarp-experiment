// This code is originally based on ASP.NET ISessionStore (https://github.com/dotnet/aspnetcore/blob/main/src/Middleware/Session/src/ISessionStore.cs), but it's different:
// We intentionally don't support session establishing (tryEstablishSession parameter) since it's the responsibility of a gateway.

using System;
using Microsoft.AspNetCore.Http;

namespace Distributed.Session
{
    /// <summary>
    /// Storage for sessions that maintain user data while the user browses a web application.
    /// </summary>
    public interface ISessionStore
	{
        /// <summary>
        /// Create a new or resume an <see cref="ISession"/>.
        /// </summary>
        /// <param name="sessionKey">A unique key used to lookup the session.</param>
        /// <param name="idleTimeout">How long the session can be inactive (e.g. not accessed) before it will expire.</param>
        /// <param name="ioTimeout">
        /// The maximum amount of time <see cref="ISession.LoadAsync(System.Threading.CancellationToken)"/> and
        /// <see cref="ISession.CommitAsync(System.Threading.CancellationToken)"/> are allowed take.
        /// </param>
        /// <param name="isNewSessionKey"><see langword="true"/> if establishing a new session; <see langword="false"/> if resuming a session.</param>
        /// <returns>The <see cref="ISession"/> that was created or resumed.</returns>
        ISession Create(string sessionKey, TimeSpan idleTimeout, TimeSpan ioTimeout, bool isNewSessionKey);

        /// <summary>
        /// Deletes a distibuted session with all its data (removes it completely from backing store)
        /// </summary>
        /// <param name="sessionKey">A unique key used to lookup the session.</param>
        void Destroy(string sessionKey);
    }
}

