using System;
using System.Linq;
using Microsoft.AspNetCore.Http;

namespace Distributed.Permissions
{
	/// <summary>
	/// Collection of methods related to permissions in HttpContext
	/// </summary>
	public static class HttpContextExtensions
	{
		/// <summary>
		/// Get the collection of permissions
		/// </summary>
		/// <param name="context">The current context</param>
		/// <returns>The permissions (string desriptors)</returns>
		public static string[] Permissions(this HttpContext context)
			// Take from session
			=> context.Session.Permissions();

		/// <summary>
		/// Check for permission in the context
		/// </summary>
		/// <param name="context">The current context</param>
		/// <param name="permission">The permission to check (string descriptor)/param>
		/// <returns>Is permission present?</returns>
		public static bool HasPermission(this HttpContext context, string permission)
			=> context.Permissions().Contains(permission);
    }
}

