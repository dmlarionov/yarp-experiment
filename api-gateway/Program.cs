using System.Text.Json;
using System.Text.Json.Serialization;
using ApiGateway;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();   // console logging

builder.Services.AddControllersWithViews();

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.AddHttpClient("Auth-Service-Client", config =>
{
    var url = builder.Configuration.GetValue<string>("AuthorizationService.Address");
    if (url == null)
        throw new Exception("AuthorizationService.Address isn't configured! It must be HTTP(s) endpoint.");
    config.BaseAddress = new Uri(url);
});

builder.Services.AddAuthentication(AuthenticationDefaults.AuthenticationScheme)
    .AddXCookie(AuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/auth/login";
        options.AccessDeniedPath = "/auth/accessdenied";
    });

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
app.MapReverseProxy();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Demo}/{action=Index}/{id?}");

app.Run();
