using CustomJWTWith2FA.Models;
using Microsoft.EntityFrameworkCore;

namespace CustomJWTWith2FA.Data;

public class ApplicationDbContext : DbContext
{
    public DbSet<User> Users { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
}