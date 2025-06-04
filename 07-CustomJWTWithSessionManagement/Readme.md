# Project Setup

Start with the `CustomJWTWithSessionManagement` project or ensure the following NuGet packages are installed:

```bash
dotnet new webapi -n CustomJWTWithSessionManagement
cd CustomJWTWithSessionManagement
```

```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package System.IdentityModel.Tokens.Jwt
dotnet add package Otp.NET
dotnet add package QRCoder
dotnet add package Scalar.AspNetCore
```

# Implementation

## 1. Update Models for Session Tracking

Update `Models/User.cs` to include a `Sessions` collection for tracking logins:

```csharp
using System.Security.Cryptography;
using System.Text;

namespace CustomJWTWithSessionManagement.Models
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
        public List<Session> Sessions { get; set; } = new List<Session>();
    }

    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; }
        public int UserId { get; set; }
        public User User { get; set; }
        public int SessionId { get; set; }
        public Session Session { get; set; }
    }

    public class Session
    {
        public int Id { get; set; }
        public string SessionToken { get; set; }
        public DateTime LoginTimestamp { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public bool IsActive { get; set; }
        public DateTime? LastActivity { get; set; }
        public string DeviceFingerprint { get; set; } // Optional
        public int UserId { get; set; }
        public User User { get; set; }
        public List<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
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

Update `Data/ApplicationDbContext.cs` to include the `Sessions` table:

```csharp
using Microsoft.EntityFrameworkCore;
using CustomJWTWithSessionManagement.Models;

namespace CustomJWTWithSessionManagement.Data
{
    public class ApplicationDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<Session> Sessions { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
    }
}
```

Run migrations to update the database schema:

```bash
dotnet ef migrations add AddSessionManagement
dotnet ef database update
```

## 3. Session Service

Create `Services/SessionService.cs` to handle session creation and fingerprinting:

```csharp
using CustomJWTWithSessionManagement.Models;
using System.Security.Cryptography;
using System.Text;

namespace CustomJWTWithSessionManagement.Services
{
    public class SessionService
    {
        public string GenerateSessionToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public string GenerateDeviceFingerprint(string ipAddress, string userAgent)
        {
            // Simple fingerprint: hash of IP + User-Agent
            var input = $"{ipAddress}:{userAgent}";
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(input);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash)[..16]; // Truncate for brevity
        }

        public Session CreateSession(string username, string ipAddress, string userAgent)
        {
            return new Session
            {
                SessionToken = GenerateSessionToken(),
                LoginTimestamp = DateTime.UtcNow,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                IsActive = true,
                LastActivity = DateTime.UtcNow,
                DeviceFingerprint = GenerateDeviceFingerprint(ipAddress, userAgent)
            };
        }
    }
}
```

Register the service in `Program.cs` (before `app.Build()`):

```csharp
builder.Services.AddSingleton<SessionService>();
```

## 4. Update JWT Service

Update `Services/JwtService.cs` to include session token in JWT claims:

```csharp
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;

namespace CustomJWTWithSessionManagement.Services
{
    public class JwtService
    {
        private readonly IConfiguration _configuration;

        public JwtService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateAccessToken(string username, string role, bool is2FAVerified, string sessionToken)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role),
                new Claim("2FAVerified", is2FAVerified.ToString()),
                new Claim("SessionToken", sessionToken)
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

## 5. Update Program.cs

Update `Program.cs` to include session management services:

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using CustomJWTWithSessionManagement.Data;
using CustomJWTWithSessionManagement.Services;
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

// Add Authorization Policy for 2FA
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("2FARequired", policy => policy.RequireClaim("2FAVerified", "True"));
});

builder.Services.AddSingleton<JwtService>();
builder.Services.AddSingleton<TwoFactorService>();
builder.Services.AddSingleton<SessionService>();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", builder =>
    {
        builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseCors("AllowAll");
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

## 6. Update Auth Controller

Update `Controllers/AuthController.cs` to manage sessions during login, 2FA verification, and provide session management endpoints:

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CustomJWTWithSessionManagement.Data;
using CustomJWTWithSessionManagement.Models;
using CustomJWTWithSessionManagement.Services;

namespace CustomJWTWithSessionManagement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly JwtService _jwtService;
        private readonly TwoFactorService _twoFactorService;
        private readonly SessionService _sessionService;
        private readonly IConfiguration _configuration;

        public AuthController(ApplicationDbContext context, JwtService jwtService, TwoFactorService twoFactorService, SessionService sessionService, IConfiguration configuration)
        {
            _context = context;
            _jwtService = jwtService;
            _twoFactorService = twoFactorService;
            _sessionService = sessionService;
            _configuration = configuration;
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

            var session = _sessionService.CreateSession(user.Username, HttpContext.Connection.RemoteIpAddress?.ToString(), HttpContext.Request.Headers["User-Agent"]);
            user.Sessions.Add(session);
            await _context.SaveChangesAsync();

            if (user.Is2FAEnabled)
            {
                return Ok(new { Requires2FA = true, Username = user.Username, SessionToken = session.SessionToken });
            }

            var accessToken = _jwtService.GenerateAccessToken(user.Username, user.Role, is2FAVerified: true, session.SessionToken);
            var refreshToken = _jwtService.GenerateRefreshToken();

            user.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                Expires = DateTime.Now.AddDays(7),
                IsRevoked = false,
                UserId = user.Id,
                SessionId = session.Id
            });
            await _context.SaveChangesAsync();

            return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken, SessionToken = session.SessionToken });
        }

        [HttpPost("verify-2fa")]
        public async Task<IActionResult> Verify2FA([FromBody] Verify2FAModel model)
        {
            var user = await _context.Users.Include(u => u.Sessions).FirstOrDefaultAsync(u => u.Username == model.Username);
            if (user == null || !user.Is2FAEnabled)
            {
                return Unauthorized("Invalid user or 2FA not enabled");
            }

            var session = user.Sessions.FirstOrDefault(s => s.SessionToken == model.SessionToken && s.IsActive);
            if (session == null)
            {
                return Unauthorized("Invalid session");
            }

            if (!_twoFactorService.Verify2FACode(user.TwoFactorSecret, model.Code))
            {
                return Unauthorized("Invalid 2FA code");
            }

            session.LastActivity = DateTime.UtcNow;
            var accessToken = _jwtService.GenerateAccessToken(user.Username, user.Role, is2FAVerified: true, session.SessionToken);
            var refreshToken = _jwtService.GenerateRefreshToken();

            user.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                Expires = DateTime.Now.AddDays(7),
                IsRevoked = false,
                UserId = user.Id,
                SessionId = session.Id
            });
            await _context.SaveChangesAsync();

            return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken, SessionToken = session.SessionToken });
        }

        [HttpGet("setup-2fa")]
        [Authorize(Policy = "2FARequired")]
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
        [Authorize(Policy = "2FARequired")]
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
            var sessionToken = principal.FindFirst("SessionToken")?.Value;
            var is2FAVerified = principal.FindFirst("2FAVerified")?.Value == "True";
            if (!is2FAVerified)
            {
                return Unauthorized("2FA verification required");
            }

            var user = await _context.Users.Include(u => u.RefreshTokens).Include(u => u.Sessions)
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

            var session = user.Sessions.FirstOrDefault(s => s.Id == refreshToken.SessionId && s.IsActive);
            if (session == null)
            {
                return Unauthorized("Invalid session");
            }

            session.LastActivity = DateTime.UtcNow;
            var newAccessToken = _jwtService.GenerateAccessToken(user.Username, user.Role, is2FAVerified: true, session.SessionToken);
            var newRefreshToken = _jwtService.GenerateRefreshToken();

            refreshToken.IsRevoked = true;
            user.RefreshTokens.Add(new RefreshToken
            {
                Token = newRefreshToken,
                Expires = DateTime.Now.AddDays(7),
                IsRevoked = false,
                UserId = user.Id,
                SessionId = session.Id
            });
            await _context.SaveChangesAsync();

            return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken, SessionToken = session.SessionToken });
        }

        [HttpPost("revoke")]
        [Authorize(Policy = "2FARequired")]
        public async Task<IActionResult> Revoke([FromBody] RevokeTokenModel model)
        {
            var user = await _context.Users.Include(u => u.RefreshTokens).Include(u => u.Sessions)
                .FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (user == null)
            {
                return Unauthorized("Invalid user");
            }

            var session = user.Sessions.FirstOrDefault(s => s.SessionToken == model.SessionToken && s.IsActive);
            if (session == null)
            {
                return BadRequest("Invalid session");
            }

            session.IsActive = false;
            session.LastActivity = DateTime.UtcNow;
            foreach (var token in user.RefreshTokens.Where(t => t.SessionId == session.Id && !t.IsRevoked))
            {
                token.IsRevoked = true;
            }
            await _context.SaveChangesAsync();

            return Ok("Session revoked successfully");
        }

        [HttpPost("revoke-all-others")]
        [Authorize(Policy = "2FARequired")]
        public async Task<IActionResult> RevokeAllOtherSessions()
        {
            var user = await _context.Users.Include(u => u.RefreshTokens).Include(u => u.Sessions)
                .FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (user == null)
            {
                return Unauthorized("Invalid user");
            }

            var currentSessionToken = User.FindFirst("SessionToken")?.Value;
            foreach (var session in user.Sessions.Where(s => s.SessionToken != currentSessionToken && s.IsActive))
            {
                session.IsActive = false;
                session.LastActivity = DateTime.UtcNow;
                foreach (var token in user.RefreshTokens.Where(t => t.SessionId == session.Id && !t.IsRevoked))
                {
                    token.IsRevoked = true;
                }
            }
            await _context.SaveChangesAsync();

            return Ok("All other sessions revoked successfully");
        }

        [HttpGet("sessions")]
        [Authorize(Policy = "2FARequired")]
        public async Task<IActionResult> GetSessions()
        {
            var user = await _context.Users.Include(u => u.Sessions)
                .FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (user == null)
            {
                return Unauthorized("Invalid user");
            }

            var sessions = user.Sessions.Select(s => new
            {
                s.SessionToken,
                s.LoginTimestamp,
                s.IpAddress,
                s.UserAgent,
                s.IsActive,
                s.LastActivity,
                s.DeviceFingerprint
            }).ToList();

            return Ok(sessions);
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
        public string SessionToken { get; set; }
    }

    public class RefreshTokenModel
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }

    public class RevokeTokenModel
    {
        public string SessionToken { get; set; }
    }
}
```

## 7. Update UI

Update `wwwroot/index.html` to display and manage sessions:

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>2FA Authentication</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-gray-100 flex items-center justify-center h-screen">
    <div class="bg-white p-8 rounded-lg shadow-lg w-full max-w-md">
      <h1 class="text-2xl font-bold mb-6 text-center">2FA Authentication</h1>
      <div id="auth-section">
        <div id="login-form" class="space-y-4">
          <h2 class="text-xl font-semibold">Login</h2>
          <input
            id="login-username"
            type="text"
            placeholder="Username"
            class="w-full p-2 border rounded"
          />
          <input
            id="login-password"
            type="password"
            placeholder="Password"
            class="w-full p-2 border rounded"
          />
          <button
            onclick="login()"
            class="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
          >
            Login
          </button>
          <button
            onclick="showRegister()"
            class="w-full text-blue-500 underline"
          >
            Register
          </button>
        </div>
        <div id="register-form" class="space-y-4 hidden">
          <h2 class="text-xl font-semibold">Register</h2>
          <input
            id="register-username"
            type="text"
            placeholder="Username"
            class="w-full p-2 border rounded"
          />
          <input
            id="register-password"
            type="password"
            placeholder="Password"
            class="w-full p-2 border rounded"
          />
          <select id="register-role" class="w-full p-2 border rounded">
            <option value="User">User</option>
            <option value="Admin">Admin</option>
          </select>
          <button
            onclick="register()"
            class="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
          >
            Register
          </button>
          <button onclick="showLogin()" class="w-full text-blue-500 underline">
            Back to Login
          </button>
        </div>
        <div id="2fa-form" class="space-y-4 hidden">
          <h2 class="text-xl font-semibold">Enter 2FA Code</h2>
          <input id="2fa-username" type="hidden" />
          <input id="2fa-session-token" type="hidden" />
          <input
            id="2fa-code"
            type="text"
            placeholder="6-digit code"
            class="w-full p-2 border rounded"
          />
          <button
            onclick="verify2FA()"
            class="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
          >
            Verify
          </button>
        </div>
      </div>
      <div id="dashboard" class="hidden space-y-4">
        <h2 class="text-xl font-semibold">Dashboard</h2>
        <p>Welcome, <span id="username"></span>!</p>
        <div id="2fa-status" class="mb-4"></div>
        <div id="2fa-setup" class="hidden space-y-4">
          <h3 class="text-lg font-semibold">Setup 2FA</h3>
          <img id="qrcode" class="mx-auto hidden" alt="QR Code" />
          <p>Manual Code: <span id="manual-code" class="font-mono"></span></p>
          <p>Enter the manual code in your authenticator app.</p>
        </div>
        <button
          id="toggle-2fa"
          onclick="toggle2FA()"
          class="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600"
        ></button>
        <button
          onclick="getAssets()"
          class="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
        >
          View Assets
        </button>
        <h3 class="text-lg font-semibold">Active Sessions</h3>
        <ul id="sessions-list" class="space-y-2"></ul>
        <button
          onclick="revokeAllOtherSessions()"
          class="w-full bg-yellow-500 text-white p-2 rounded hover:bg-yellow-600"
        >
          Logout All Other Sessions
        </button>
        <button
          onclick="logout()"
          class="w-full bg-red-500 text-white p-2 rounded hover:bg-red-600"
        >
          Logout
        </button>
      </div>
      <p id="error" class="text-red-500 mt-4 hidden"></p>
    </div>
    <script src="/js/app.js"></script>
  </body>
</html>
```

Update `wwwroot/js/app.js` to handle session management:

```javascript
let accessToken = null;
let refreshToken = null;
let sessionToken = null;

function showLogin() {
  document.getElementById("login-form").classList.remove("hidden");
  document.getElementById("register-form").classList.add("hidden");
  document.getElementById("2fa-form").classList.add("hidden");
  document.getElementById("dashboard").classList.add("hidden");
  document.getElementById("error").classList.add("hidden");
}

function showRegister() {
  document.getElementById("login-form").classList.add("hidden");
  document.getElementById("register-form").classList.remove("hidden");
  document.getElementById("2fa-form").classList.add("hidden");
  document.getElementById("dashboard").classList.add("hidden");
  document.getElementById("error").classList.add("hidden");
}

function show2FA(username, sessionToken) {
  document.getElementById("login-form").classList.add("hidden");
  document.getElementById("register-form").classList.add("hidden");
  document.getElementById("2fa-form").classList.remove("hidden");
  document.getElementById("dashboard").classList.add("hidden");
  document.getElementById("2fa-username").value = username;
  document.getElementById("2fa-session-token").value = sessionToken;
  document.getElementById("error").classList.add("hidden");
}

async function register() {
  const username = document.getElementById("register-username").value;
  const password = document.getElementById("register-password").value;
  const role = document.getElementById("register-role").value;

  try {
    const response = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, role }),
    });
    if (response.ok) {
      showLogin();
    } else {
      const error = await response.text();
      showError(error || "Registration failed");
    }
  } catch (err) {
    showError("Registration failed");
  }
}

async function login() {
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;

  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await response.json();
    if (response.ok) {
      if (data.requires2FA) {
        show2FA(data.username, data.sessionToken);
      } else {
        accessToken = data.accessToken;
        refreshToken = data.refreshToken;
        sessionToken = data.sessionToken;
        showDashboard(data.username);
      }
    } else {
      showError(data || "Login failed");
    }
  } catch (err) {
    showError("Login failed");
  }
}

async function verify2FA() {
  const username = document.getElementById("2fa-username").value;
  const code = document.getElementById("2fa-code").value;
  const sessionToken = document.getElementById("2fa-session-token").value;

  try {
    const response = await fetch("/api/auth/verify-2fa", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, code, sessionToken }),
    });
    const data = await response.json();
    if (response.ok) {
      accessToken = data.accessToken;
      refreshToken = data.refreshToken;
      sessionToken = data.sessionToken;
      showDashboard(username);
    } else {
      showError("Invalid 2FA code");
    }
  } catch (err) {
    showError("2FA verification failed");
  }
}

async function showDashboard(username) {
  document.getElementById("auth-section").classList.add("hidden");
  document.getElementById("dashboard").classList.remove("hidden");
  document.getElementById("username").textContent = username;

  try {
    const response = await fetch("/api/auth/setup-2fa", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (response.ok) {
      const data = await response.json();
      document.getElementById("2fa-status").textContent = "2FA is enabled";
      document.getElementById("toggle-2fa").textContent = "Disable 2FA";
      document.getElementById("2fa-setup").classList.remove("hidden");
      document.getElementById("qrcode").classList.add("hidden");
      document.getElementById("manual-code").textContent = data.manualCode;
    } else {
      document.getElementById("2fa-status").textContent = "2FA is disabled";
      document.getElementById("toggle-2fa").textContent = "Enable 2FA";
      document.getElementById("2fa-setup").classList.add("hidden");
    }
  } catch (err) {
    document.getElementById("2fa-status").textContent = "2FA is disabled";
    document.getElementById("toggle-2fa").textContent = "Enable 2FA";
    document.getElementById("2fa-setup").classList.add("hidden");
  }

  await loadSessions();
}

async function toggle2FA() {
  const isEnabled =
    document.getElementById("2fa-status").textContent === "2FA is enabled";
  const endpoint = isEnabled ? "/api/auth/disable-2fa" : "/api/auth/setup-2fa";

  try {
    console.log(`Calling ${endpoint} with token: ${accessToken}`);
    const response = await fetch(endpoint, {
      method: isEnabled ? "POST" : "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    });
    if (response.ok) {
      const contentType = response.headers.get("content-type");
      let data;
      if (contentType && contentType.includes("application/json")) {
        data = await response.json();
      } else {
        data = { message: await response.text() };
      }
      if (!isEnabled) {
        document.getElementById("2fa-status").textContent = "2FA is enabled";
        document.getElementById("toggle-2fa").textContent = "Disable 2FA";
        document.getElementById("2fa-setup").classList.remove("hidden");
        document.getElementById("qrcode").classList.add("hidden");
        document.getElementById("manual-code").textContent = data.manualCode;
      } else {
        document.getElementById("2fa-status").textContent = "2FA is disabled";
        document.getElementById("toggle-2fa").textContent = "Enable 2FA";
        document.getElementById("2fa-setup").classList.add("hidden");
      }
    } else {
      const error = await response.text();
      showError(`Failed to toggle 2FA: ${error || response.statusText}`);
    }
  } catch (err) {
    console.error("Toggle2FA error:", err);
    showError("Failed to toggle 2FA");
  }
}

async function loadSessions() {
  try {
    const response = await fetch("/api/auth/sessions", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (response.ok) {
      const sessions = await response.json();
      const sessionsList = document.getElementById("sessions-list");
      sessionsList.innerHTML = "";
      sessions.forEach((session) => {
        const li = document.createElement("li");
        li.className = "border p-2 rounded flex justify-between items-center";
        li.innerHTML = `
                    <div>
                        <p><strong>Login:</strong> ${new Date(
                          session.loginTimestamp
                        ).toLocaleString()}</p>
                        <p><strong>IP:</strong> ${session.ipAddress}</p>
                        <p><strong>Device:</strong> ${session.userAgent}</p>
                        <p><strong>Active:</strong> ${session.isActive}</p>
                        <p><strong>Fingerprint:</strong> ${
                          session.deviceFingerprint
                        }</p>
                    </div>
                    ${
                      session.isActive && session.sessionToken !== sessionToken
                        ? `<button onclick="revokeSession('${session.sessionToken}')" class="bg-red-500 text-white p-1 rounded hover:bg-red-600">Revoke</button>`
                        : ""
                    }
                `;
        sessionsList.appendChild(li);
      });
    } else {
      showError("Failed to load sessions");
    }
  } catch (err) {
    showError("Failed to load sessions");
  }
}

async function revokeSession(sessionToken) {
  try {
    const response = await fetch("/api/auth/revoke", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ sessionToken }),
    });
    if (response.ok) {
      await loadSessions();
    } else {
      showError("Failed to revoke session");
    }
  } catch (err) {
    showError("Failed to revoke session");
  }
}

async function revokeAllOtherSessions() {
  try {
    const response = await fetch("/api/auth/revoke-all-others", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    });
    if (response.ok) {
      await loadSessions();
    } else {
      showError("Failed to revoke other sessions");
    }
  } catch (err) {
    showError("Failed to revoke other sessions");
  }
}

async function getAssets() {
  try {
    const response = await fetch("/api/assets", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (response.ok) {
      const data = await response.text();
      alert(data);
    } else if (response.status === 401) {
      await refreshTokenAndRetry();
    } else {
      showError("Failed to fetch assets");
    }
  } catch (err) {
    showError("Failed to fetch assets");
  }
}

async function refreshTokenAndRetry() {
  try {
    const response = await fetch("/api/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ accessToken, refreshToken }),
    });
    if (response.ok) {
      const data = await response.json();
      accessToken = data.accessToken;
      refreshToken = data.refreshToken;
      sessionToken = data.sessionToken;
      await getAssets();
    } else {
      showError("Session expired. Please log in again.");
      showLogin();
    }
  } catch (err) {
    showError("Session expired. Please log in again.");
    showLogin();
  }
}

function logout() {
  accessToken = null;
  refreshToken = null;
  sessionToken = null;
  showLogin();
}

function showError(message) {
  const error = document.getElementById("error");
  error.textContent = message;
  error.classList.remove("hidden");
}
```

## 8. Update appsettings.json

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

# Session Management Features

- **Per-Session Login Tracking**: Each login creates a `Session` with a unique `SessionToken`, linked to the user and refresh tokens.
- **Login Details**: Captures `LoginTimestamp`, `IpAddress`, `UserAgent`, and `DeviceFingerprint` (optional SHA256 hash of IP + User-Agent).
- **Token Revocation**: The `/api/auth/revoke` endpoint revokes a specific session by deactivating it and revoking associated refresh tokens.
- **Active Session List**: The `/api/auth/sessions` endpoint returns all sessions for the user, shown in the UI with details and revoke buttons.
- **Force Logout Other Sessions**: The `/api/auth/revoke-all-others` endpoint deactivates all sessions except the current one.
- **Device Fingerprinting**: Optional feature using a hashed combination of IP and User-Agent to distinguish devices.

# Security Notes

- **Session Storage**: Sessions and refresh tokens are stored securely in SQLite, linked to users.
- **JWT**: Short-lived (15 minutes) with `SessionToken` claim; refresh tokens are long-lived (7 days) and revokable.
- **TOTP**: 2FA remains enforced with manual code entry (QR code disabled).
- **Password Hashing**: PBKDF2 with SHA256, 100,000 iterations, 16-byte salt.
- **HTTPS**: Enforced via `UseHttpsRedirection`.
- **CORS**: Permissive for development; restrict in production.

# Running the App

1. Run `dotnet run`.
2. Access `https://localhost:5001` to load the UI.
3. Register a user (e.g., `test`/`Password123`/`User`).
4. Log in, enable 2FA, and enter the manual code in an authenticator app.
5. On the dashboard, view active sessions, revoke specific sessions, or log out all other sessions.
6. Test session tracking by logging in from multiple browsers/devices.

# Testing

- Log in with `admin`/`Password123` from different browsers to create multiple sessions.
- Verify session details (timestamp, IP, User-Agent, fingerprint) in the UI.
- Revoke a session and confirm it’s marked inactive.
- Use “Logout All Other Sessions” to terminate other sessions.
- Test protected endpoints (`/api/assets`) to ensure session validation.

# Next Steps

- Add session expiration (e.g., auto-deactivate after 30 days).
- Enhance device fingerprinting with more attributes (e.g., screen resolution).
- Implement recovery codes for 2FA.
- Use a secure key management system (e.g., Azure Key Vault).
- Restrict CORS in production.

This implementation provides robust session management similar to Google/GitHub, integrated with JWT and 2FA. Let me know if you need further refinements or additional features!
