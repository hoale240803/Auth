# Project Setup

Start with the `CustomJWTWithRefresh` project or create a new ASP.NET Core Web API project:

```bash
dotnet new webapi -n CustomJWTWith2FA
cd CustomJWTWith2FA
```

Add required NuGet packages:

```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package System.IdentityModel.Tokens.Jwt
dotnet add package OtpNet
dotnet add package QRCoder
dotnet add package Scalar.AspNetCore
```

# Implementation

## 1. Update Models for 2FA

Update `Models/User.cs` to include 2FA properties:

```csharp
using System.Security.Cryptography;
using System.Text;

namespace CustomJWTWith2FA.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public string Role { get; set; }
        public bool Is2FAEnabled { get; set; }
        public string TwoFactorSecret { get; set; }
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

Update `Data/ApplicationDbContext.cs` to include the updated `User` model:

```csharp
using Microsoft.EntityFrameworkCore;
using CustomJWTWith2FA.Models;

namespace CustomJWTWith2FA.Data
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

Run migrations to update the database schema for 2FA fields:

```bash
dotnet ef migrations add Add2FAFields
dotnet ef database update
```

## 3. Update JWT Service

Update `Services/JwtService.cs` to include 2FA status in JWT claims:

```csharp
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;

namespace CustomJWTWith2FA.Services
{
    public class JwtService
    {
        private readonly IConfiguration _configuration;

        public JwtService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateAccessToken(string username, string role, bool is2FAVerified)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role),
                new Claim("2FAVerified", is2FAVerified.ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(15),
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
                ValidateLifetime = false
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

## 4. 2FA Service

Create `Services/TwoFactorService.cs` to handle TOTP generation and QR code creation:

```csharp
using OtpNet;
using QRCoder;
using System.Text;

namespace CustomJWTWith2FA.Services
{
    public class TwoFactorService
    {
        public (string secret, string qrCodeUrl) Generate2FASecret(string username, string issuer)
        {
            var secretKey = KeyGeneration.GenerateRandomKey(20);
            var secret = Base32Encoding.ToString(secretKey);
            var qrCodeUrl = $"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}";
            return (secret, qrCodeUrl);
        }

        public string GenerateQrCodePng(string qrCodeUrl)
        {
            using var qrGenerator = new QRCodeGenerator();
            var qrCodeData = qrGenerator.CreateQrCode(qrCodeUrl, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            var qrCodeBytes = qrCode.GetGraphic(20);
            return Convert.ToBase64String(qrCodeBytes);
        }

        public bool Verify2FACode(string secret, string code)
        {
            var secretBytes = Base32Encoding.ToBytes(secret);
            var totp = new Totp(secretBytes);
            return totp.VerifyTotp(code, out _, new VerificationWindow(1));
        }
    }
}
```

Register the service in `Program.cs` (add before `app.Build()`):

```csharp
builder.Services.AddSingleton<TwoFactorService>();
```

## 5. Update Program.cs

Update `Program.cs` to configure services and seed data:

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using CustomJWTWith2FA.Data;
using CustomJWTWith2FA.Services;
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
builder.Services.AddSingleton<TwoFactorService>();
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

## 6. Update Seed Data

Update `Data/SeedData.cs` to seed a test user without 2FA enabled:

```csharp
using CustomJWTWith2FA.Models;
using Microsoft.EntityFrameworkCore;

namespace CustomJWTWith2FA.Data
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
                    Role = "Admin",
                    Is2FAEnabled = false
                });
                await context.SaveChangesAsync();
            }
        }
    }
}
```

## 7. Update Auth Controller

Update `Controllers/AuthController.cs` to handle 2FA setup, enable/disable, and login with OTP:

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CustomJWTWith2FA.Data;
using CustomJWTWith2FA.Models;
using CustomJWTWith2FA.Services;

namespace CustomJWTWith2FA.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly JwtService _jwtService;
        private readonly TwoFactorService _twoFactorService;

        public AuthController(ApplicationDbContext context, JwtService jwtService, TwoFactorService twoFactorService)
        {
            _context = context;
            _jwtService = jwtService;
            _twoFactorService = twoFactorService;
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
                Role = model.Role ?? "User",
                Is2FAEnabled = false
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

            if (user.Is2FAEnabled)
            {
                return Ok(new { Requires2FA = true, Username = user.Username });
            }

            var accessToken = _jwtService.GenerateAccessToken(user.Username, user.Role, is2FAVerified: true);
            var refreshToken = _jwtService.GenerateRefreshToken();

            user.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                Expires = DateTime.Now.AddDays(7),
                IsRevoked = false,
                UserId = user.Id
            });
            await _context.SaveChangesAsync();

            return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
        }

        [HttpPost("verify-2fa")]
        public async Task<IActionResult> Verify2FA([FromBody] Verify2FAModel model)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
            if (user == null || !user.Is2FAEnabled)
            {
                return Unauthorized("Invalid user or 2FA not enabled");
            }

            if (!_twoFactorService.Verify2FACode(user.TwoFactorSecret, model.Code))
            {
                return Unauthorized("Invalid 2FA code");
            }

            var accessToken = _jwtService.GenerateAccessToken(user.Username, user.Role, is2FAVerified: true);
            var refreshToken = _jwtService.GenerateRefreshToken();

            user.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                Expires = DateTime.Now.AddDays(7),
                IsRevoked = false,
                UserId = user.Id
            });
            await _context.SaveChangesAsync();

            return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
        }

        [HttpGet("setup-2fa")]
        [Authorize]
        public async Task<IActionResult> Setup2FA()
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (user == null)
            {
                return Unauthorized("Invalid user");
            }

            var (secret, qrCodeUrl) = _twoFactorService.Generate2FASecret(user.Username, _configuration["Jwt:Issuer"]);
            var qrCodePng = _twoFactorService.GenerateQrCodePng(qrCodeUrl);

            user.TwoFactorSecret = secret;
            user.Is2FAEnabled = true;
            await _context.SaveChangesAsync();

            return Ok(new { QrCode = qrCodePng, ManualCode = secret });
        }

        [HttpPost("disable-2fa")]
        [Authorize]
        public async Task<IActionResult> Disable2FA()
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (user == null)
            {
                return Unauthorized("Invalid user");
            }

            user.Is2FAEnabled = false;
            user.TwoFactorSecret = null;
            await _context.SaveChangesAsync();

            return Ok("2FA disabled successfully");
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenModel model)
        {
            var principal = _jwtService.GetPrincipalFromExpiredToken(model.AccessToken);
            var username = principal.Identity?.Name;
            var is2FAVerified = principal.FindFirst("2FAVerified")?.Value == "True";
            if (!is2FAVerified)
            {
                return Unauthorized("2FA verification required");
            }

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

            var newAccessToken = _jwtService.GenerateAccessToken(user.Username, user.Role, is2FAVerified: true);
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
        [Authorize]
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

    public class Verify2FAModel
    {
        public string Username { get; set; }
        public string Code { get; set; }
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

## 8. Update Assets Controller

Update `Controllers/AssetsController.cs` to require 2FA verification:

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CustomJWTWith2FA.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy = "2FARequired")]
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

Add a 2FA policy in `Program.cs` (before `app.Build()`):

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("2FARequired", policy => policy.RequireClaim("2FAVerified", "True"));
});
```

## 9. Update appsettings.json

Ensure `appsettings.json` is configured:

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

- **TOTP**: Uses `OtpNet` for TOTP generation/verification, compatible with Google Authenticator, Microsoft Authenticator, etc.
- **QR Code**: Generated using `QRCoder`, returned as base64 PNG for scanning; manual code provided as fallback.
- **2FA Storage**: Secret stored securely in SQLite, linked to user.
- **Access Token**: Short-lived (15 minutes) JWT with `2FAVerified` claim.
- **Refresh Token**: Longer-lived (7 days), revokable, and stored in SQLite.
- **Password Hashing**: PBKDF2 with SHA256, 100,000 iterations, 16-byte salt.
- **HTTPS**: Enforced via `UseHttpsRedirection`.
- **JWT Validation**: Middleware validates issuer, audience, and signature; refresh endpoint allows expired tokens.

# Running the App

1. Run `dotnet run`.
2. Access `https://localhost:5001/swagger` to test APIs via Swagger UI.
3. Register a user: `POST /api/auth/register` with JSON like `{ "username": "test", "password": "Password123", "role": "User" }`.
4. Login: `POST /api/auth/login` with JSON like `{ "username": "test", "password": "Password123" }`.
   - If 2FA is enabled, response includes `Requires2FA` and `Username`.
   - If 2FA is disabled, response includes `AccessToken` and `RefreshToken`.
5. Verify 2FA: `POST /api/auth/verify-2fa` with JSON like `{ "username": "test", "code": "123456" }` to get tokens.
6. Setup 2FA: `GET /api/auth/setup-2fa` (authenticated) to get QR code (base64 PNG) and manual code.
7. Disable 2FA: `POST /api/auth/disable-2fa` (authenticated).
8. Refresh: `POST /api/auth/refresh` with JSON like `{ "accessToken": "<expired-jwt>", "refreshToken": "<refresh-token>" }`.
9. Revoke: `POST /api/auth/revoke` with JSON like `{ "refreshToken": "<refresh-token>" }`.
10. Use the access token in the `Authorization` header (`Bearer <token>`) to access `/api/assets`.

# Testing

- Use the seeded `admin` user (`admin`/`Password123`) to test (2FA disabled by default).
- Enable 2FA via `/api/auth/setup-2fa`, scan the QR code with an authenticator app, and verify with `/api/auth/verify-2fa`.
- Test refresh and revoke endpoints with 2FA-enabled users.
- Access `/api/assets` to confirm 2FA verification is required.

# Next Steps

- Add client-side QR code rendering (e.g., display base64 PNG in a web UI).
- Implement recovery codes for 2FA fallback.
- Add cleanup for expired refresh tokens.
- Use a secure key management system (e.g., Azure Key Vault) for the JWT key.
- Enhance Swagger with JWT and 2FA support.

This implementation adds secure TOTP-based 2FA to the JWT authentication system, providing robust security for your internal API. Let me know if you need further refinements or additional features!
