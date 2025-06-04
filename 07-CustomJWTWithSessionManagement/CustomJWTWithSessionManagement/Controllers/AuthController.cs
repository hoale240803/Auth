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
                Is2FAEnabled = false,
                TwoFactorSecret = "supersecret"
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

            var refreshToken = new RefreshToken
            {
                Token = _jwtService.GenerateRefreshToken(),
                Expires = DateTime.Now.AddDays(7),
                IsRevoked = false,
                SessionId = session.Id
            };
            session.RefreshToken = refreshToken;
            await _context.SaveChangesAsync();

            var accessToken = _jwtService.GenerateAccessToken(user.Username, user.Role, is2FAVerified: true, session.SessionToken);
            return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken.Token, SessionToken = session.SessionToken });
        }

        [HttpPost("verify-2fa")]
        public async Task<IActionResult> Verify2FA([FromBody] Verify2FAModel model)
        {
            var user = await _context.Users.Include(u => u.Sessions).ThenInclude(s => s.RefreshToken)
                .FirstOrDefaultAsync(u => u.Username == model.Username);
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
            var refreshToken = new RefreshToken
            {
                Token = _jwtService.GenerateRefreshToken(),
                Expires = DateTime.Now.AddDays(7),
                IsRevoked = false,
                SessionId = session.Id
            };
            _context.RefreshTokens.Update(refreshToken);
            await _context.SaveChangesAsync();

            var accessToken = _jwtService.GenerateAccessToken(user.Username, user.Role, is2FAVerified: true, session.SessionToken);
            return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken.Token, SessionToken = session.SessionToken });
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
            user.TwoFactorSecret = "supersecret"; // Reset to a default value
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

            var user = await _context.Users.Include(u => u.Sessions).ThenInclude(s => s.RefreshToken)
                .FirstOrDefaultAsync(u => u.Username == username);
            if (user == null)
            {
                return Unauthorized("Invalid user");
            }

            var session = user.Sessions.FirstOrDefault(s => s.SessionToken == sessionToken && s.IsActive);
            if (session == null || session.RefreshToken == null || session.RefreshToken.Token != model.RefreshToken || session.RefreshToken.IsRevoked || session.RefreshToken.Expires <= DateTime.Now)
            {
                return Unauthorized("Invalid or expired refresh token");
            }

            session.LastActivity = DateTime.UtcNow;
            session.RefreshToken.Token = _jwtService.GenerateRefreshToken();
            session.RefreshToken.Expires = DateTime.Now.AddDays(7);
            session.RefreshToken.IsRevoked = false;

            await _context.SaveChangesAsync();

            var newAccessToken = _jwtService.GenerateAccessToken(user.Username, user.Role, is2FAVerified: true, session.SessionToken);
            return Ok(new { AccessToken = newAccessToken, RefreshToken = session.RefreshToken.Token, SessionToken = session.SessionToken });
        }

        [HttpPost("revoke")]
        [Authorize(Policy = "2FARequired")]
        public async Task<IActionResult> Revoke([FromBody] RevokeTokenModel model)
        {
            var user = await _context.Users.Include(u => u.Sessions).ThenInclude(s => s.RefreshToken)
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
            if (session.RefreshToken != null)
            {
                session.RefreshToken.IsRevoked = true;
            }
            await _context.SaveChangesAsync();

            return Ok("Session revoked successfully");
        }

        [HttpPost("revoke-all-others")]
        [Authorize(Policy = "2FARequired")]
        public async Task<IActionResult> RevokeAllOtherSessions()
        {
            var user = await _context.Users.Include(u => u.Sessions).ThenInclude(s => s.RefreshToken)
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
                if (session.RefreshToken != null)
                {
                    session.RefreshToken.IsRevoked = true;
                }
            }
            await _context.SaveChangesAsync();

            return Ok("All other sessions revoked successfully");
        }

        [HttpGet("sessions")]
        [Authorize(Policy = "2FARequired")]
        public async Task<IActionResult> GetSessions()
        {
            var user = await _context.Users.Include(u => u.Sessions).ThenInclude(s => s.RefreshToken)
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
                s.DeviceFingerprint,
                RefreshTokenStatus = s.RefreshToken != null ? (s.RefreshToken.IsRevoked ? "Revoked" : s.RefreshToken.Expires > DateTime.Now ? "Active" : "Expired") : "None"
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