# Project Setup

1. Start with the previous `IdentityIntro` project or create a new ASP.NET Core MVC project:

```bash
dotnet new mvc -n IdentityRolesAndClaims
cd IdentityRolesAndClaims
```

2. Add required NuGet packages:

```bash
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
dotnet add package Microsoft.EntityFrameworkCore.Design
```

# Implementation

## 1. Configure Identity with Roles and SQLite

Update `Program.cs` to include Identity with roles and claims-based authorization policies.

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using IdentityRolesAndClaims.Data;

var builder = WebApplication.CreateBuilder(args);

// Configure SQLite database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Identity with roles
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Define authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanCreateAsset", policy =>
        policy.RequireClaim("Permission", "Asset.Create"));
    options.AddPolicy("CanEditAsset", policy =>
        policy.RequireClaim("Permission", "Asset.Edit"));
    options.AddPolicy("CanDeleteAsset", policy =>
        policy.RequireClaim("Permission", "Asset.Delete"));
    options.AddPolicy("CanViewAsset", policy =>
        policy.RequireClaim("Permission", "Asset.View"));
    options.AddPolicy("CanCommentAsset", policy =>
        policy.RequireClaim("Permission", "Asset.Comment"));
    options.AddPolicy("CanManageUsers", policy =>
        policy.RequireClaim("Permission", "User.Manage"));
});

builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication().AddCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Seed roles and users (for demo purposes)
using (var scope = app.Services.CreateScope())
{
    await SeedData.Initialize(scope.ServiceProvider);
}

app.Run();
```

Create `Data/ApplicationDbContext.cs` for the EF Core context:

```csharp
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityRolesAndClaims.Data
{
    public class ApplicationDbContext : IdentityDbContext<IdentityUser, IdentityRole, string>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
    }
}
```

Create `Data/SeedData.cs` to initialize roles and users with claims:

```csharp
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace IdentityRolesAndClaims.Data
{
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
}
```

Update `appsettings.json` with the connection string:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=app.db"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  }
}
```

Run migrations:

```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

## 2. Account Controller

Update `Controllers/AccountController.cs` to handle login, registration, and logout, integrating roles and claims.

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace IdentityRolesAndClaims.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpGet]
        public IActionResult Login() => View();

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            var result = await _signInManager.PasswordSignInAsync(username, password, isPersistent: false, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                return RedirectToAction("Index", "Home");
            }
            ViewBag.Error = "Invalid credentials";
            return View();
        }

        [HttpGet]
        public IActionResult Register() => View();

        [HttpPost]
        public async Task<IActionResult> Register(string username, string password, string role)
        {
            var user = new IdentityUser { UserName = username, Email = username + "@example.com" };
            var result = await _userManager.CreateAsync(user, password);
            if (result.Succeeded)
            {
                if (!string.IsNullOrEmpty(role))
                {
                    await _userManager.AddToRoleAsync(user, role);
                    var permissions = role switch
                    {
                        "ITManager" => new[] { "Asset.Create", "Asset.Edit", "Asset.Delete", "Asset.View", "Asset.Comment" },
                        "Developer" => new[] { "Asset.View", "Asset.Comment" },
                        "HelpdeskManager" => new[] { "Asset.View", "User.Manage" },
                        _ => new[] { "Asset.View" }
                    };
                    foreach (var permission in permissions)
                    {
                        await _userManager.AddClaimAsync(user, new Claim("Permission", permission));
                    }
                }
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("Index", "Home");
            }
            ViewBag.Errors = result.Errors.Select(e => e.Description);
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login");
        }
    }
}
```

## 3. Asset Controller

Create `Controllers/AssetController.cs` to demonstrate resource-specific permissions.

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityRolesAndClaims.Controllers
{
    [Authorize]
    public class AssetController : Controller
    {
        [Authorize(Policy = "CanViewAsset")]
        public IActionResult View() => Content($"Viewing assets as {User.Identity.Name}");

        [Authorize(Policy = "CanCreateAsset")]
        public IActionResult Create() => Content($"Creating asset as {User.Identity.Name}");

        [Authorize(Policy = "CanEditAsset")]
        public IActionResult Edit() => Content($"Editing asset as {User.Identity.Name}");

        [Authorize(Policy = "CanDeleteAsset")]
        public IActionResult Delete() => Content($"Deleting asset as {User.Identity.Name}");

        [Authorize(Policy = "CanCommentAsset")]
        public IActionResult Comment() => Content($"Commenting on asset as {User.Identity.Name}");

        [Authorize(Policy = "CanManageUsers")]
        public IActionResult ManageUsers() => Content($"Managing users as {User.Identity.Name}");
    }
}
```

## 4. Views

Update `Views/Account/Login.cshtml`:

```html
@model dynamic
<h2>Login</h2>
@if (ViewBag.Error != null) { <p style="color:red">@ViewBag.Error</p> }
<form method="post">
    <label>Username</label><input type="text" name="username" required /><br />
    <label>Password</label><input type="password" name="password" required /><br />
    <button type="submit">Login</button>
    <a href="@Url.Action("Register")">Register</a>
</form>
```

Update `Views/Account/Register.cshtml`:

```html
@model dynamic
<h2>Register</h2>
@if (ViewBag.Errors != null) {
    <ul style="color:red">
        @foreach (var error in ViewBag.Errors) { <li>@error</li> }
    </ul>
}
<form method="post">
    <label>Username</label><input type="text" name="username" required /><br />
    <label>Password</label><input type="password" name="password" required /><br />
    <label>Role</label>
    <select name="role">
        <option value="ITManager">IT Manager</option>
        <option value="Developer">Developer</option>
        <option value="HelpdeskManager">Helpdesk Manager</option>
        <option value="Others">Others</option>
    </select><br />
    <button type="submit">Register</button>
    <a href="@Url.Action("Login")">Back to Login</a>
</form>
```

Update `Views/Home/Index.cshtml` to show role-based actions:

```html
<h2>Welcome, @User.Identity.Name!</h2>
<ul>
    @if (User.HasClaim("Permission", "Asset.View")) {
        <li><a href="@Url.Action("View", "Asset")">View Assets</a></li>
    }
    @if (User.HasClaim("Permission", "Asset.Create")) {
        <li><a href="@Url.Action("Create", "Asset")">Create Asset</a></li>
    }
    @if (User.HasClaim("Permission", "Asset.Edit")) {
        <li><a href="@Url.Action("Edit", "Asset")">Edit Asset</a></li>
    }
    @if (User.HasClaim("Permission", "Asset.Delete")) {
        <li><a href="@Url.Action("Delete", "Asset")">Delete Asset</a></li>
    }
    @if (User.HasClaim("Permission", "Asset.Comment")) {
        <li><a href="@Url.Action("Comment", "Asset")">Comment on Asset</a></li>
    }
    @if (User.HasClaim("Permission", "User.Manage")) {
        <li><a href="@Url.Action("ManageUsers", "Asset")">Manage Users</a></li>
    }
</ul>
<form method="post" action="@Url.Action("Logout", "Account")">
    <button type="submit">Logout</button>
</form>
```

# Avoiding Duplicate Logic

- **Claims-Based Policies**: Permissions like `Asset.Create`, `Asset.Edit`, etc., are stored as claims and checked via policies (`CanCreateAsset`, etc.) in the `Authorize` attribute, eliminating repetitive `if` checks in controllers.
- **Centralized Authorization**: Policies defined in `Program.cs` ensure consistent permission checks across the app.
- **Role-to-Claim Mapping**: Roles (e.g., ITManager) are associated with specific claims during user creation, reducing manual permission assignments.
- **Dynamic UI**: The view checks claims (e.g., `User.HasClaim`) to show only relevant actions, avoiding hardcoded role checks.

# Security Notes

- **Claims-Based Authorization**: Fine-grained permissions (e.g., `Asset.Create`) are more flexible than role-based checks.
- **Password Hashing**: ASP.NET Core Identity uses PBKDF2 with HMAC-SHA256.
- **SQLite**: Lightweight for internal apps; use a production database for scale.
- **HTTPS**: Enforced via `UseHttpsRedirection`.
- **CSRF**: Built-in protection with form tags.

# Running the App

1. Run `dotnet run`.
2. Access `https://localhost:5001` (port may vary).
3. Register or log in with seeded users (e.g., `itmanager`/`Password123`) to test role-based permissions.
4. Navigate to the home page to see permission-specific actions.

# Role Permissions

- **IT Manager**: Full control (`Asset.Create`, `Asset.Edit`, `Asset.Delete`, `Asset.View`, `Asset.Comment`).
- **Developer**: Read-only + comment (`Asset.View`, `Asset.Comment`).
- **Helpdesk Manager**: View assets + manage users (`Asset.View`, `User.Manage`).
- **Others**: Limited to view (`Asset.View`).

# Next Steps

- Add a UI for managing roles and claims (e.g., for Helpdesk Manager).
- Implement resource-specific permissions (e.g., per-asset access).
- Add audit logging for permission changes.
- Use a production database like SQL Server for scalability.
- Enhance UI with a framework like Bootstrap.

This implementation provides a secure, maintainable solution for role-based permissions while avoiding duplicate logic through claims and policies. Let me know if you need further refinements or additional features!
