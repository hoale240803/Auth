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