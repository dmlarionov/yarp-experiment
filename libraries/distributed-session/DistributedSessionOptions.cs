using System;
using System.Reflection.PortableExecutable;
using Microsoft.AspNetCore.Http;

// The distributed session options are controversial thing: what if timeouts are differently configured for various microservices?

namespace Distributed.Session
{
    /// <summary>
    /// Represents the session state options for the application.
    /// </summary>
    public class DistributedSessionOptions
    {
        /// <summary>
        /// The IdleTimeout indicates how long the session can be idle before its contents are abandoned. Each session access
        /// resets the timeout.
        /// </summary>
        public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(20);

        /// <summary>
        /// The maximum amount of time allowed to load a session from the store or to commit it back to the store.
        /// Note this may only apply to asynchronous operations. This timeout can be disabled using <see cref="Timeout.InfiniteTimeSpan"/>.
        /// </summary>
        public TimeSpan IOTimeout { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>
        /// The header name to propagate session key.
        /// </summary>
        public string PropagationHeaderName { get; set; } = SessionDefaults.PropagationHeaderName;
    }
}

