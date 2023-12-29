using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace Distributed.Authentication
{
	public class AuthenticationOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// The application name to use for data protector.
        /// Must match with application name on the gateway side, please override this via options.
        /// </summary>
        public string ApplicationName { get; set; } = AuthenticationDefaults.ApplicationName;
    }
}

