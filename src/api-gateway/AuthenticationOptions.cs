﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace ApiGateway;

public class AuthenticationOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Used inside HandleChallengeAsync to redirect the user to the login page.
    /// </summary>
    public PathString LoginPath { get; set; } = AuthenticationDefaults.LoginPath;

    /// <summary>
    /// Used inside HandleForbidenAsync to redirect the user to the access denied page.
    /// </summary>
    public PathString AccessDeniedPath { get; set; } = AuthenticationDefaults.AccessDeniedPath;

    /// <summary>
    /// How much time the cookie will be valid.
    /// </summary>
    public TimeSpan ExpireTimeSpan { get; set; } = AuthenticationDefaults.ExpireTimeSpan;

    /// <summary>
    /// Name of the authentication cookie.
    /// </summary>
    public string CookieName { get; set; } = AuthenticationDefaults.CookieName;

    /// <summary>
    /// Property added over the standard behavior.
    /// A claim named "IpAddress" is added to the identity. If this property is true, then 
    /// the requester's ip-address must match.
    /// </summary>
    public bool CheckIpAddress { get; set; } = true;

    /// <summary>
    /// Property added over the standard behavior.
    /// A claim named "UserAgent" is added to the identity. If this property is true, then 
    /// the requester's user-agent must match.
    /// </summary>
    public bool CheckUserAgent { get; set; } = true;

    /// <summary>
    /// This property is used to protect/unprotect data inside the cookie.
    /// </summary>
    internal ISecureDataFormat<AuthenticationTicket> TicketDataFormat { get; }

    public AuthenticationOptions()
    {
        var serializer = new TicketSerializer();
        var dataProtector = DataProtectionProvider.Create(typeof(AuthenticationHandler).FullName!).CreateProtector("ticket");

        TicketDataFormat = new SecureDataFormat<AuthenticationTicket>(serializer, dataProtector);
    }
}
