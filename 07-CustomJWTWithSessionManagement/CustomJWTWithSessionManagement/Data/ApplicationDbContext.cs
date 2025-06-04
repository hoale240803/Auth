using Microsoft.EntityFrameworkCore;
using CustomJWTWithSessionManagement.Models;

namespace CustomJWTWithSessionManagement.Data
{
    public class ApplicationDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<Session> Sessions { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Session>()
                .HasOne(s => s.RefreshToken)
                .WithOne(rt => rt.Session)
                .HasForeignKey<RefreshToken>(rt => rt.SessionId);
        }
    }
}