namespace ApiGateway;

public static class AuthenticationDefaults
{
    public static readonly string AuthenticationScheme  = "X-Scheme";
    public static readonly PathString ApiPath = "/api";
    public static readonly PathString LoginPath = "/auth/login";
    public static readonly PathString AccessDeniedPath = "/auth/accessdenied";
    public static readonly TimeSpan ExpireTimeSpan = TimeSpan.FromMinutes(30);
    public static readonly string CookieName = "X-Authentication";
}
