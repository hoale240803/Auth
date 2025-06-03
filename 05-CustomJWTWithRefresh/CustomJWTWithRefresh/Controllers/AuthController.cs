using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CustomJWTWithRefresh.Data;
using CustomJWTWithRefresh.Models;
using CustomJWTWithRefresh.Services;

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