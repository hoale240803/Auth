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