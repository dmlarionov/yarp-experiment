using System;
using Microsoft.Extensions.Logging;

namespace ApiGateway
{
    internal static partial class LoggingExtensions
    {
        [LoggerMessage(1, LogLevel.Information, "Session key isn't unavailable.", EventName = "SessionKeyNotAvailable")]
        public static partial void SessionKeyNotAvailable(this ILogger logger);
    }
}

