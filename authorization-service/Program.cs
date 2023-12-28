using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;
using Distributed.Session;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

var redisConnection = builder.Configuration.GetValue<string>("REDIS") ?? "localhost:6379";
var redis = ConnectionMultiplexer.Connect(redisConnection);

builder.Services
    .AddDataProtection()
    .SetApplicationName("yarn-experiment")
    .PersistKeysToStackExchangeRedis(redis, "DataProtectionKeys");

builder.Services.AddStackExchangeRedisCache(option =>
{
    option.Configuration = redisConnection;
    option.InstanceName = "SessionCache";
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

