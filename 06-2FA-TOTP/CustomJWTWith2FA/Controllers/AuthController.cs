using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CustomJWTWith2FA.Data;
using CustomJWTWith2FA.Models;
using CustomJWTWith2FA.Services;

namespace CustomJWTWith2FA.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly JwtService _jwtService;
    private readonly TwoFactorService _twoFactorService;
    private readonly IConfiguration _configuration;

    public AuthController(ApplicationDbContext context, JwtService jwtService, TwoFactorService twoFactorService, IConfiguration configuration)
    {
        _context = context;
        _jwtService = jwtService;
        _twoFactorService = twoFactorService;
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
        user.TwoFactorSecret = string.Empty;
        await _context.SaveChangesAsync();

        return Ok();
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