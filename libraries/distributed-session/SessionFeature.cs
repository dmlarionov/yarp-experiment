using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Distributed.Session
{
    /// <inheritdoc />
    public class SessionFeature : ISessionFeature
    {
        /// <inheritdoc />
        public ISession Session { get; set; } = default!;
    }
}

