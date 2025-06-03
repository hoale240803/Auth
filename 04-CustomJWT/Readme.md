# Project Setup

1. Create a new ASP.NET Core Web API project:

```bash
dotnet new webapi -n CustomJWT
cd CustomJWT
```

2. Add required NuGet packages:

```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package System.IdentityModel.Tokens.Jwt
dotnet add package Scalar.AspNetCore
```

# Implementation

## 1. User Model and Database Context

Create `Models/User.cs` for user data with password hashing:

```csharp
using System.Security.Cryptography;
using System.Text;

namespace CustomJWT.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public string Role { get; set; }
    }

    public static class PasswordHelper
    {
        public static (byte[] hash, byte[] salt) HashPassword(string password)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, 16, 100000, HashAlgorithmName.SHA256);
            return (pbkdf2.GetBytes(32), pbkdf2.Salt);
        }

        public static bool VerifyPassword(string password, byte[] storedHash, byte[] storedSalt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, storedSalt, 100000, HashAlgorithmName.SHA256);
            var hash = pbkdf2.GetBytes(32);
            return CryptographicOperations.FixedTimeEquals(hash, storedHash);
        }
    }
}
```

Create `Data/ApplicationDbContext.cs` for EF Core with SQLite:

```csharp
using Microsoft.EntityFrameworkCore;
using CustomJWT.Models;

namespace CustomJWT.Data
{
    public class ApplicationDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
    }
}
```

## 2. Configure JWT Authentication

Update `appsettings.json` with JWT settings and connection string:

```json
{
  "Jwt": {
    "Key": "YourSuperSecretKey1234567890AtLeast32BytesLong",
    "Issuer": "CustomJWTApp",
    "Audience": "CustomJWTApp"
  },
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=app.db"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  }
}
```

Update `Program.cs` to configure JWT authentication and EF Core:

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using CustomJWT.Data;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Configure SQLite
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure JWT Authentication
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSettings["Key"]);
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
```

Run migrations to create the database:

```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

## 3. JWT Generation Service

Create `Services/JwtService.cs` to generate JWT tokens:

```csharp
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CustomJWT.Services
{
    public class JwtService
    {
        private readonly IConfiguration _configuration;

        public JwtService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateToken(string username, string role)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
```

Register the service in `Program.cs` (add before `app.Build()`):

```csharp
builder.Services.AddSingleton<JwtService>();
```

## 4. Auth Controller

Create `Controllers/AuthController.cs` for login and registration APIs:

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CustomJWT.Data;
using CustomJWT.Models;
using CustomJWT.Services;

namespace CustomJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly JwtService _jwtService;

        public AuthController(ApplicationDbContext context, JwtService jwtService)
        {
            _context = context;
            _jwtService = jwtService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (await _context.Users.AnyAsync(u => u.Username == model.Username))
            {
                return BadRequest("Username already exists");
            }

            var (hash, salt) = PasswordHelper.HashPassword(model.Password);
            var user = new User
            {
                Username = model.Username,
                PasswordHash = hash,
                PasswordSalt = salt,
                Role = model.Role ?? "User"
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok("User registered successfully");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
            if (user == null || !PasswordHelper.VerifyPassword(model.Password, user.PasswordHash, user.PasswordSalt))
            {
                return Unauthorized("Invalid credentials");
            }

            var token = _jwtService.GenerateToken(user.Username, user.Role);
            return Ok(new { Token = token });
        }
    }

    public class RegisterModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }

    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
```

## 5. Protected API Controller

Create `Controllers/AssetsController.cs` to demonstrate secured routes:

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CustomJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class AssetsController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetAssets()
        {
            return Ok($"Assets viewed by {User.Identity.Name}");
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult CreateAsset()
        {
            return Ok($"Asset created by {User.Identity.Name}");
        }
    }
}
```

## 6. Seed Data (Optional)

Create `Data/SeedData.cs` to seed a test user:

```csharp
using CustomJWT.Models;
using Microsoft.EntityFrameworkCore;

namespace CustomJWT.Data
{
    public static class SeedData
    {
        public static async Task Initialize(ApplicationDbContext context)
        {
            if (!await context.Users.AnyAsync())
            {
                var (hash, salt) = PasswordHelper.HashPassword("Password123");
                context.Users.Add(new User
                {
                    Username = "admin",
                    PasswordHash = hash,
                    PasswordSalt = salt,
                    Role = "Admin"
                });
                await context.SaveChangesAsync();
            }
        }
    }
}
```

Call it in `Program.cs` before `app.Run()`:

```csharp
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await SeedData.Initialize(context);
}
```

## 7. Update **launchSettings.json**

```
    "http": {
      "commandName": "Project",
      "dotnetRunMessages": true,
      "launchBrowser": true,
      "launchUrl": "scalar/v1",
      "applicationUrl": "http://localhost:5000",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      },
    }
```

# Security Notes

- **JWT**: Tokens include username and role claims, signed with HMAC-SHA256, and expire after 1 hour.
- **Password Hashing**: PBKDF2 with SHA256, 100,000 iterations, and 16-byte salt.
- **HTTPS**: Enforced via `UseHttpsRedirection`.
- **Validation**: Middleware validates JWT issuer, audience, and signature.
- **SQLite**: Lightweight for internal apps; use a production database for scale.
- **Secret Key**: Store the JWT key securely (e.g., Azure Key Vault) in production.

# Running the App

1. Run `dotnet run`.
2. Access `https://localhost:5001/swagger` to test APIs via Swagger UI.
3. Register a user: `POST /api/auth/register` with JSON like `{ "username": "test", "password": "Password123", "role": "User" }`.
4. Login: `POST /api/auth/login` with JSON like `{ "username": "test", "password": "Password123" }` to get a JWT.
5. Use the JWT in the `Authorization` header (`Bearer <token>`) to access `/api/assets`.

# Testing

- Use the seeded `admin` user (`admin`/`Password123`) to test the `CreateAsset` endpoint (Admin role required).
- Register a user with role `User` to test the `GetAssets` endpoint (no role restriction).

# Next Steps

- Add refresh tokens for long-lived sessions.
- Implement role-based claims in JWT for finer-grained permissions.
- Add input validation for API models.
- Use a production database like SQL Server.
- Enhance Swagger with JWT authentication support.

This setup provides a secure, scalable JWT-based authentication system for your internal API. Let me know if you need further customization or additional features!
