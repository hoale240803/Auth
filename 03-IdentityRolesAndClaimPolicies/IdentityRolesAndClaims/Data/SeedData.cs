using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace IdentityRolesAndClaims.Data;

public static class SeedData
{
    public static async Task Initialize(IServiceProvider serviceProvider)
    {
        var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var userManager = serviceProvider.GetRequiredService<UserManager<IdentityUser>>();

        string[] roleNames = { "ITManager", "Developer", "HelpdeskManager", "Others" };
        foreach (var roleName in roleNames)
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new IdentityRole(roleName));
            }
        }

        var users = new[]
        {
                new { Username = "itmanager", Role = "ITManager", Permissions = new[] { "Asset.Create", "Asset.Edit", "Asset.Delete", "Asset.View", "Asset.Comment" } },
                new { Username = "developer", Role = "Developer", Permissions = new[] { "Asset.View", "Asset.Comment" } },
                new { Username = "helpdesk", Role = "HelpdeskManager", Permissions = new[] { "Asset.View", "User.Manage" } },
                new { Username = "other", Role = "Others", Permissions = new[] { "Asset.View" } }
            };

        foreach (var u in users)
        {
            var user = await userManager.FindByNameAsync(u.Username);
            if (user == null)
            {
                user = new IdentityUser { UserName = u.Username, Email = u.Username + "@example.com" };
                await userManager.CreateAsync(user, "Password123");
                await userManager.AddToRoleAsync(user, u.Role);
                foreach (var permission in u.Permissions)
                {
                    await userManager.AddClaimAsync(user, new Claim("Permission", permission));
                }
            }
        }
    }
}