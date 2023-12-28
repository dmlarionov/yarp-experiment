using System;
namespace Distributed.Session
{
    /// <summary>
    /// Represents defaults for the Session.
    /// </summary>
    public static class SessionDefaults
	{
        /// <summary>
        /// The default propagation header name.
        /// </summary>
        public static readonly string PropagationHeaderName = "X-Session";

        public static readonly string SessionHeaderProtectorPurpose = "Session Header";
    }
}