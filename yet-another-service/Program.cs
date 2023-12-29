using Distributed.Authentication;
using Distributed.Session;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

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

builder.Services.AddAuthentication()
    .AddDistributedAuthentication(options =>
    {
        options.ApplicationName = "yarn-experiment";
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("powerpolicy", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireRole("power");
    });
});

// Add distributed session services
builder.Services.AddDistributedSession();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

// Use distributed session middleware
app.UseDistributedSession();

app.MapControllers();

app.Run();

