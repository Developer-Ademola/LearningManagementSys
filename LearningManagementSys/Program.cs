using FluentValidation.AspNetCore;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Text;
using LearningManagementSys.Data;
using LearningManagementSys.Models;
using LearningManagementSys.Services;
using LearningManagementSys.Validators;

var builder = WebApplication.CreateBuilder(args);

// ✅ Load Configuration
var configuration = builder.Configuration;

// ✅ Add Controllers & FluentValidation
builder.Services.AddControllers()
    .AddFluentValidation(fv => fv.RegisterValidatorsFromAssemblyContaining<AppUserValidator>());

// ✅ Register Validators
builder.Services.AddScoped<IValidator<AppUser>, AppUserValidator>();
builder.Services.AddScoped<IValidator<LoginRequest>, LoginRequestValidator>();
builder.Services.AddScoped<IValidator<ResetPasswordRequest>, ResetPasswordRequestValidator>();
builder.Services.AddScoped<IValidator<VerificationToken>, VerificationTokenValidator>();

// ✅ Register Application Services
builder.Services.AddSingleton<CosmosDbService>(); // CosmosDB Service
builder.Services.AddSingleton<EmailService>();   // Email Service
builder.Services.AddSingleton<TokenService>();   // Token Service

// ✅ Load JWT configuration
var jwtKey = configuration["Jwt:Key"];
if (string.IsNullOrEmpty(jwtKey) || jwtKey.Length < 32)
    throw new Exception("JWT Key must be at least 32 characters long.");

// ✅ Configure JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = configuration["Jwt:Issuer"],   // ✅ Ensure this matches the token's "iss"
            ValidAudience = configuration["Jwt:Audience"], // ✅ Ensure this matches the token's "aud"
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            RoleClaimType = ClaimTypes.Role // ✅ Ensures role validation works
        };
    });

builder.Services.AddAuthorization();
// ✅ Enable Swagger & API Documentation
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer' followed by your token"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();

// ✅ Configure Middleware Pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication(); // ✅ Ensure authentication middleware is added
app.UseAuthorization();
app.MapControllers();
app.Run();