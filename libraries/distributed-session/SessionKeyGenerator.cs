using System;
using System.Security.Cryptography;

namespace Distributed.Session
{
    /// <summary>
    /// The helper to generate a session key
    /// </summary>
	public static class SessionKeyGenerator
	{
        /// <summary>
        /// The session key generator
        /// </summary>
        /// <returns>New session key</returns>
        public static string GetSessionKey()
        {
            // The code is borrowed from original ASP.NET session middleware (https://github.com/dotnet/aspnetcore/blob/main/src/Middleware/Session/src/SessionMiddleware.cs) under MIT licence
            Span<byte> guidBytes = stackalloc byte[16];
            RandomNumberGenerator.Fill(guidBytes);
            return new Guid(guidBytes).ToString();
        }
    }
}

