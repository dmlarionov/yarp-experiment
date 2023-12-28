// This code is originally based on ASP.NET (https://github.com/dotnet/aspnetcore/blob/main/src/Middleware/Session/src/SessionMiddlewareExtensions.cs), but enables our own distributed session middleware.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;

//namespace Microsoft.AspNetCore.Builder;
namespace Distributed.Session;

/// <summary>
/// Extension methods for adding the <see cref="DistributedSessionMiddleware"/> to an application.
/// </summary>
public static class SessionMiddlewareExtensions
{
    /// <summary>
    /// Adds the <see cref="DistributedSessionMiddleware"/> to automatically enable session state for the application.
    /// </summary>
    /// <param name="app">The <see cref="IApplicationBuilder"/>.</param>
    /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
    public static IApplicationBuilder UseDistributedSession(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseMiddleware<DistributedSessionMiddleware>();
    }

    /// <summary>
    /// Adds the <see cref="DistributedSessionMiddleware"/> to automatically enable session state for the application.
    /// </summary>
    /// <param name="app">The <see cref="IApplicationBuilder"/>.</param>
    /// <param name="options">The <see cref="DistributedSessionOptions"/>.</param>
    /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
    public static IApplicationBuilder UseDistributedSession(this IApplicationBuilder app, DistributedSessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(options);

        return app.UseMiddleware<DistributedSessionMiddleware>(Options.Create(options));
    }
}
