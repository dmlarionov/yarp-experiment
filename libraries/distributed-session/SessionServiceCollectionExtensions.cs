// This code is originally based on ASP.NET (https://github.com/dotnet/aspnetcore/blob/main/src/Middleware/Session/src/SessionServiceCollectionExtensions.cs), but intentionally doesn't configure Data Protection automatically to make it explicit for a user.

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

//namespace Microsoft.Extensions.DependencyInjection;
namespace Distributed.Session;

/// <summary>
/// Extension methods for adding session services to the DI container.
/// </summary>
public static class SessionServiceCollectionExtensions
{
    /// <summary>
    /// Adds services required for distributed application session state.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    [RequiresUnreferencedCode("Session State middleware does not currently support trimming or native AOT.", Url = "https://aka.ms/aspnet/trimming")]
    public static IServiceCollection AddDistributedSession(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddTransient<ISessionStore, DistributedSessionStore>();
        // We configure Data Protection separately
        return services;
    }

    /// <summary>
    /// Adds services required for distributed application session state.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="configure">The session options to configure the middleware with.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    [RequiresUnreferencedCode("Session State middleware does not currently support trimming or native AOT.", Url = "https://aka.ms/aspnet/trimming")]
    public static IServiceCollection AddDistributedSession(this IServiceCollection services, Action<DistributedSessionOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.AddDistributedSession();

        return services;
    }
}
