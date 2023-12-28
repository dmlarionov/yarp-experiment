using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;
using Distributed.Session;
using ApiGateway;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();   // console logging

// Add services to the container.

var redisConnection = builder.Configuration.GetValue<string>("REDIS") ?? "localhost:6379";
var redis = ConnectionMultiplexer.Connect(redisConnection);

// Add data protection with shared key on readis. Those keys are used to encrypt headers / cookies.
builder.Services
    .AddDataProtection()
    .SetApplicationName("yarn-experiment")
    .PersistKeysToStackExchangeRedis(redis, "DataProtectionKeys");

// Add Redis for distributed session store
builder.Services.AddStackExchangeRedisCache(option =>
{
    option.Configuration = redisConnection;
    option.InstanceName = "SessionCache";
});

// Add distributed session store (used by AuthorizationHandler)
builder.Services.AddDistributedSession();

// Add controllers (including AuthController)
builder.Services.AddControllersWithViews();

// Add reverse proxy (YARP)
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    // Add transform to propagate session header for all the routes
    .AddTransforms(builderContext =>
    {
        var headerProtector = builderContext.Services.GetDataProtector(nameof(DistributedSessionMiddleware));
        var cookieProtector = builderContext.Services.GetDataProtector(nameof(DistributedSessionGatewayMiddleware));

        // Added to all routes.
        builderContext.AddPathPrefix("/");

        builderContext.AddRequestTransform(requestContext =>
        {
            // for authorized session (authenticated user) propagate from claim
            if (requestContext.HttpContext.User.Identity?.IsAuthenticated ?? false)
            {
                var sessionKey = requestContext.HttpContext.User.Claims.Where(x => x.Type == AuthenticationHandler.SessionKeyClaimType).FirstOrDefault()?.Value;

                // if session key is present propagate it
                if (!string.IsNullOrEmpty(sessionKey))
                {
                    var headerValue = SessionProtection.Protect(headerProtector, sessionKey);
                    // You must use the same header name you've used in distributed session options..
                    // take attention if you've configured options via builder.Services.AddDistributedSession(options => ...)
                    requestContext.ProxyRequest.Headers.Add(SessionDefaults.PropagationHeaderName!, headerValue);
                }
            }
            // for unauthorized session propagate from cookie
            else
            {
                var cookieValue = requestContext.HttpContext.Request.Cookies[DistributedSessionGatewayMiddleware.UnauthorizedSessionCookieName];
                if (!string.IsNullOrEmpty(cookieValue))
                {
                    var sessionKey = SessionProtection.Unprotect(cookieProtector, cookieValue);
                    if (!string.IsNullOrWhiteSpace(sessionKey))
                    {
                        var headerValue = SessionProtection.Protect(headerProtector, sessionKey);
                        // You must use the same header name you've used in distributed session options..
                        // take attention if you've configured options via builder.Services.AddDistributedSession(options => ...)
                        requestContext.ProxyRequest.Headers.Add(SessionDefaults.PropagationHeaderName!, headerValue);
                    }
                }
            }

            return default;
        });
    });

// Configure client for the authorization service

builder.Services.AddHttpClient("Auth-Service-Client", config =>
{
    var url = builder.Configuration.GetValue<string>("AuthorizationService.Address");
    if (url == null)
        throw new Exception("AuthorizationService.Address isn't configured! It must be HTTP(s) endpoint.");
    config.BaseAddress = new Uri(url);
    // TODO: Add session header propagation to HttpClient configuration, take it out of AuthController
});

// Configure authentication

builder.Services.AddAuthentication(AuthenticationDefaults.AuthenticationScheme)
    .AddXCookie(AuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/auth/login";
        options.AccessDeniedPath = "/auth/accessdenied";
    });

// We combine edge level and service level authorization
// See https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html#edge-level-authorization
// Here we add authorization policies for the edge level

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("authenticated", policy =>
    {
        policy.RequireAuthenticatedUser();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/auth/error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// The distributed session gateway middleware manages session cookies
app.UseMiddleware<DistributedSessionGatewayMiddleware>();
app.MapReverseProxy();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Demo}/{action=Index}/{id?}");

app.Run();
