using CustomJWTWithSessionManagement.Data;
using CustomJWTWithSessionManagement.Models;
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
                    Is2FAEnabled = false,
                    TwoFactorSecret = "supersecretkey",
                });
                await context.SaveChangesAsync();
            }
        }
    }
}