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