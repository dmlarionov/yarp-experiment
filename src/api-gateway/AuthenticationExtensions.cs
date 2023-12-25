using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace ApiGateway
{
	public static class AuthenticationExtensions
	{
        public static AuthenticationBuilder AddXCookie(this AuthenticationBuilder builder)
        {
            return builder.AddXCookie(AuthenticationDefaults.AuthenticationScheme, null, null!);
        }

        public static AuthenticationBuilder AddXCookie(this AuthenticationBuilder builder, string authenticationScheme)
        {
            return builder.AddXCookie(authenticationScheme, null, null!);
        }

        public static AuthenticationBuilder AddXCookie(this AuthenticationBuilder builder, string authenticationScheme, Action<AuthenticationOptions> configureOptions)
        {
            return builder.AddXCookie(authenticationScheme, null, configureOptions);
        }

        public static AuthenticationBuilder AddXCookie(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<AuthenticationOptions> configureOptions)
        {
            return builder.AddScheme<AuthenticationOptions, AuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}

