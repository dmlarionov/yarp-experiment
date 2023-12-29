using System;
using Microsoft.Extensions.Logging;

namespace Distributed.Authentication
{
    internal static partial class LoggingExtensions
    {
        [LoggerMessage(1, LogLevel.Warning, "Error unprotecting the authentication ticket.", EventName = "ErrorUnprotectingTicket")]
        public static partial void ErrorUnprotectingTicket(this ILogger logger, Exception exception);
    }
}

