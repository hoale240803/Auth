# Project Setup

Start with the `CustomJWT` project from the previous step or create a new ASP.NET Core Web API project:

```bash
dotnet new webapi -n CustomJWTWithRefresh
cd CustomJWTWithRefresh
```

Add required NuGet packages (same as before):

```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package System.IdentityModel.Tokens.Jwt
```

# Implementation

## 1. Update Models for Refresh Tokens

Update `Models/User.cs` to include refresh token storage:

```csharp
using System.Security.Cryptography;
using System.Text;

namespace CustomJWTWithRefresh.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public string Role { get; set; }
        public List<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }

    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; }
        public int UserId { get; set; }
        public User User { get; set; }
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

## 2. Update Database Context

Update `Data/ApplicationDbContext.cs` to include the `RefreshTokens` table:

```csharp
using Microsoft.EntityFrameworkCore;
using CustomJWTWithRefresh.Models;

namespace CustomJWTWithRefresh.Data
{
    public class ApplicationDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
    }
}
```

Run migrations to update the database schema:

```bash
dotnet ef migrations add AddRefreshTokens
dotnet ef database update
```

## 3. Update JWT Service for Refresh Tokens

Update `Services/JwtService.cs` to handle refresh token generation and validation:

```csharp
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;

namespace CustomJWTWithRefresh.Services
{
    public class JwtService
    {
        private readonly IConfiguration _configuration;

        public JwtService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateAccessToken(string username, string role)
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
                expires: DateTime.Now.AddMinutes(15), // Short-lived access token
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateLifetime = false // Allow expired tokens for refresh
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }
    }
}
```

## 4. Update Program.cs

Update `Program.cs` to configure services and seed data:

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using CustomJWTWithRefresh.Data;
using CustomJWTWithRefresh.Services;
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

builder.Services.AddSingleton<JwtService>();
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

// Seed data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await SeedData.Initialize(context);
}

app.Run();
```

## 5. Update Seed Data

Update `Data/SeedData.cs` to seed a test user:

```csharp
using CustomJWTWithRefresh.Models;
using Microsoft.EntityFrameworkCore;

namespace CustomJWTWithRefresh.Data
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

## 6. Update Auth Controller

Update `Controllers/AuthController.cs` to handle login, refresh token exchange, and revocation:

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CustomJWTWithRefresh.Data;
using CustomJWTWithRefresh.Models;
using CustomJWTWithRefresh.Services;
using System.Security.Claims;

namespace CustomJWTWithRefresh.Controllers
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

            var accessToken = _jwtService.GenerateAccessToken(user.Username, user.Role);
            var refreshToken = _jwtService.GenerateRefreshToken();

            user.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                Expires = DateTime.Now.AddDays(7), // Longer-lived refresh token
                IsRevoked = false,
                UserId = user.Id
            });
            await _context.SaveChangesAsync();

            return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenModel model)
        {
            var principal = _jwtService.GetPrincipalFromExpiredToken(model.AccessToken);
            var username = principal.Identity?.Name;
            var user = await _context.Users.Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.Username == username);

            if (user == null)
            {
                return Unauthorized("Invalid user");
            }

            var refreshToken = user.RefreshTokens.FirstOrDefault(t => t.Token == model.RefreshToken && !t.IsRevoked && t.Expires > DateTime.Now);
            if (refreshToken == null)
            {
                return Unauthorized("Invalid or expired refresh token");
            }

            var newAccessToken = _jwtService.GenerateAccessToken(user.Username, user.Role);
            var newRefreshToken = _jwtService.GenerateRefreshToken();

            refreshToken.IsRevoked = true;
            user.RefreshTokens.Add(new RefreshToken
            {
                Token = newRefreshToken,
                Expires = DateTime.Now.AddDays(7),
                IsRevoked = false,
                UserId = user.Id
            });
            await _context.SaveChangesAsync();

            return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken });
        }

        [HttpPost("revoke")]
        public async Task<IActionResult> Revoke([FromBody] RevokeTokenModel model)
        {
            var user = await _context.Users.Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (user == null)
            {
                return Unauthorized("Invalid user");
            }

            var refreshToken = user.RefreshTokens.FirstOrDefault(t => t.Token == model.RefreshToken && !t.IsRevoked);
            if (refreshToken == null)
            {
                return BadRequest("Invalid refresh token");
            }

            refreshToken.IsRevoked = true;
            await _context.SaveChangesAsync();

            return Ok("Refresh token revoked");
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

    public class RefreshTokenModel
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }

    public class RevokeTokenModel
    {
        public string RefreshToken { get; set; }
    }
}
```

## 7. Update Assets Controller

The `Controllers/AssetsController.cs` remains unchanged from the previous step, as it already supports JWT authentication:

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CustomJWTWithRefresh.Controllers
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

## 8. Update appsettings.json

Ensure `appsettings.json` is configured (same as before):

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

# Security Notes

- **Access Token**: Short-lived (15 minutes) JWT with username and role claims, signed with HMAC-SHA256.
- **Refresh Token**: Longer-lived (7 days), stored in SQLite, revokable, and randomly generated for security.
- **Storage**: Refresh tokens are securely stored in the database, linked to users, with expiration and revocation tracking.
- **Password Hashing**: PBKDF2 with SHA256, 100,000 iterations, and 16-byte salt.
- **HTTPS**: Enforced via `UseHttpsRedirection`.
- **JWT Validation**: Middleware validates issuer, audience, and signature; refresh endpoint allows expired access tokens.
- **Revocation**: Refresh tokens can be revoked explicitly via the `/api/auth/revoke` endpoint.

# Running the App

1. Run `dotnet run`.
2. Access `https://localhost:5001/swagger` to test APIs via Swagger UI.
3. Register a user: `POST /api/auth/register` with JSON like `{ "username": "test", "password": "Password123", "role": "User" }`.
4. Login: `POST /api/auth/login` with JSON like `{ "username": "test", "password": "Password123" }` to get an access token and refresh token.
5. Refresh: `POST /api/auth/refresh` with JSON like `{ "accessToken": "<expired-jwt>", "refreshToken": "<refresh-token>" }` to get a new access token and refresh token.
6. Revoke: `POST /api/auth/revoke` with JSON like `{ "refreshToken": "<refresh-token>" }` to revoke a refresh token.
7. Use the access token in the `Authorization` header (`Bearer <token>`) to access `/api/assets`.

# Testing

- Use the seeded `admin` user (`admin`/`Password123`) to test the `CreateAsset` endpoint (Admin role required).
- Register a user with role `User` to test the `GetAssets` endpoint.
- Test token refresh by waiting for the access token to expire (15 minutes) and using the refresh endpoint.

# Next Steps

- Add claim-based permissions (e.g., `Asset.Create`) to JWTs for finer-grained authorization.
- Implement token cleanup to remove expired/revoked refresh tokens from the database.
- Use a secure key management system (e.g., Azure Key Vault) for the JWT key.
- Add input validation for API models using data annotations.
- Enhance Swagger with JWT authentication support.

This implementation adds secure refresh token functionality to the previous JWT-based system, ensuring robust authentication for your internal API. Let me know if you need further refinements or additional features!
