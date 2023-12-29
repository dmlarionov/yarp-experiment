using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Distributed.Authentication
{
	public static class AuthenticationExtensions
	{
        public static AuthenticationBuilder AddDistributedAuthentication(this AuthenticationBuilder builder)
            => builder.AddDistributedAuthentication(AuthenticationDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddDistributedAuthentication(
            this AuthenticationBuilder builder,
            string authenticationScheme)
            => builder.AddDistributedAuthentication(authenticationScheme, _ => { });

        public static AuthenticationBuilder AddDistributedAuthentication(
            this AuthenticationBuilder builder,
            Action<AuthenticationOptions> configureOptions)
            => builder.AddDistributedAuthentication(AuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddDistributedAuthentication(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            Action<AuthenticationOptions> configureOptions)
            => AddDistributedAuthentication(builder, authenticationScheme, null, configureOptions);

        public static AuthenticationBuilder AddDistributedAuthentication(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string? displayName,
            Action<AuthenticationOptions> configureOptions)
        {
            return builder.AddScheme<AuthenticationOptions, AuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}

