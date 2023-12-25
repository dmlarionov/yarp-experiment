using ApiGateway;

var builder = WebApplication.CreateBuilder(args);
//builder.Services.AddReverseProxy()
//  .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication(AuthenticationDefaults.AuthenticationScheme)
    .AddXCookie(AuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/auth/login";
        options.AccessDeniedPath = "/auth/accessdenied";
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

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Demo}/{action=Index}/{id?}");

app.Run();
