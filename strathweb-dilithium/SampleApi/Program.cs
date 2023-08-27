using Microsoft.AspNetCore.Authorization;
using Strathweb.Dilithium.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// add standard ASP.NET Core JWT Bearer middleware
builder.Services.AddAuthentication().AddJwtBearer(opt =>
{
    // point to the local IDP, capable of issuing Dilithium tokens
    opt.Authority = "https://localhost:5001";
    opt.Audience = "https://localhost:7104";
    
    // configure Dilithium token support
    opt.ConfigureDilithiumTokenSupport();
});

builder.Services.AddAuthorization(options =>
    options.AddPolicy("api", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("scope", "scope1");
    })
);

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthorization();
app.MapGet("/demo", [Authorize("api")]() => "hello, world!");

app.Run();