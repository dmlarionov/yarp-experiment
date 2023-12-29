using System;
namespace Distributed.Authentication
{
	public static class AuthenticationDefaults
	{
        /// <summary>
        /// The default authentication scheme
        /// </summary>
        public static readonly string AuthenticationScheme = "Bearer";

        /// <summary>
        /// The default application name to use for data protector.
        /// Must match with application name on the gateway side, please override this via options.
        /// </summary>
        public static readonly string ApplicationName = typeof(AuthenticationHandler).FullName!;
    }
}

