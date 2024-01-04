using System;
using System.Security;
using Microsoft.AspNetCore.Http;

namespace Distributed.Permissions
{
	public static class SessionExtensions
	{
        /// <summary>
		/// Get the collection of permissions
		/// </summary>
		/// <param name="session">The session</param>
		/// <returns>The permissions (string desriptors)</returns>
		public static string[] Permissions(this ISession session)
        {
            var unsplitted = session.GetString(PermissionDefaults.SessionKey);
            if (unsplitted != null)
                return unsplitted.Split(PermissionDefaults.Separator);
            else
                return new string[] {};
        }

        /// <summary>
        /// Append permissions to the session
        /// </summary>
        /// <param name="session">The session</param>
        /// <param name="permissions">The permissions (string desriptors) to append</param>
        public static void PermissionsAppend(this ISession session, string[] permissions)
        {
            var current = session.Permissions();
            var updated = current.Union(permissions);
            // Save to session
            session.SetString(PermissionDefaults.SessionKey, string.Join(PermissionDefaults.Separator, updated));
        }

        /// <summary>
        /// Append a permission to the session
        /// </summary>
        /// <param name="session">The session</param>
        /// <param name="permission">The permission (string desriptor) to append</param>
        public static void PermissionsAppend(this ISession session, string permission)
            => PermissionsAppend(session, new string[] { permission });

        /// <summary>
        /// Append permissions to the session
        /// </summary>
        /// <param name="session">The session</param>
        /// <param name="permissions">The permissions (string desriptors) to append</param>
        public static void PermissionsAppend(this ISession session, IEnumerable<string> permissions)
            => session.PermissionsAppend(permissions.ToArray());

        /// <summary>
        /// Remove permission from the session
        /// </summary>
        /// <param name="session">The session</param>
        /// <param name="permissions">The permissions (string desriptors) to remove</param>
        public static void PermissionsRemove(this ISession session, string[] permissions)
        {
            var current = session.Permissions();
            var updated = current.Except(permissions);
            // Save to session
            session.SetString(PermissionDefaults.SessionKey, string.Join(PermissionDefaults.Separator, updated));
        }

        /// <summary>
        /// Remove a permission from the session
        /// </summary>
        /// <param name="session">The session</param>
        /// <param name="permission">The permission (string desriptor) to remove</param>
        public static void PermissionsRemove(this ISession session, string permission)
            => PermissionsRemove(session, new string[] { permission });

        /// <summary>
        /// Remove permission from the session
        /// </summary>
        /// <param name="session">The session</param>
        /// <param name="permissions">The permissions (string desriptors) to remove</param>
        public static void PermissionsRemove(this ISession session, IEnumerable<string> permissions)
            => session.PermissionsRemove(permissions.ToArray());
    }
}

