I'll guide you through implementing a basic ASP.NET Core MVC app with ASP.NET Core Identity, using Entity Framework Core (EF Core) and SQLite for user management. This setup provides a secure, scalable authentication system with built-in features for registration, login, logout, and password hashing. The focus is on a fast and secure implementation for your internal app.

# Project Setup

1. Create a new ASP.NET Core MVC project:

```bash
dotnet new mvc -n IdentityIntro
cd IdentityIntro
```

2. Add required NuGet packages:

```bash
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
dotnet add package Microsoft.EntityFrameworkCore.Design
```

# Implementation

## 1. Configure Identity and SQLite

Update `Program.cs` to set up ASP.NET Core Identity with EF Core and SQLite.

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using IdentityIntro.Data;

var builder = WebApplication.CreateBuilder(args);

// Configure SQLite database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

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

app.Run();
```

Create `Data/ApplicationDbContext.cs` for the EF Core context:

```csharp
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityIntro.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
    }
}
```

Add a connection string in `appsettings.json`:

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

## 2. Initialize Database

Run migrations to create the SQLite database:

```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

## 3. Account Controller

Create `Controllers/AccountController.cs` to handle registration, login, and logout.

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace IdentityIntro.Controllers
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
        public IActionResult Register() => View();

        [HttpPost]
        public async Task<IActionResult> Register(string username, string password)
        {
            var user = new IdentityUser { UserName = username, Email = username + "@example.com" };
            var result = await _userManager.CreateAsync(user, password);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("Index", "Home");
            }
            ViewBag.Errors = result.Errors.Select(e => e.Description);
            return View();
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

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login");
        }
    }
}
```

## 4. Views

Create `Views/Account/Register.cshtml`:

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
    <button type="submit">Register</button>
    <a href="@Url.Action("Login")">Back to Login</a>
</form>
```

Create `Views/Account/Login.cshtml`:

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

## 5. Protected Page

Update `Controllers/HomeController.cs` to protect the Index action:

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityIntro.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public IActionResult Index() => View();
    }
}
```

Update `Views/Home/Index.cshtml`:

```html
<h2>Welcome, @User.Identity.Name!</h2>
<form method="post" action="@Url.Action("Logout", "Account")">
    <button type="submit">Logout</button>
</form>
```

# Security Notes

- **Password Hashing**: ASP.NET Core Identity uses PBKDF2 with HMAC-SHA256 by default for secure password hashing.
- **Database**: SQLite is lightweight and suitable for internal apps; consider SQL Server or PostgreSQL for production.
- **Authentication**: Cookie-based auth with a 1-hour expiration; adjust `ExpireTimeSpan` as needed.
- **HTTPS**: Enforced via `UseHttpsRedirection`.
- **Built-in Features**: Identity handles user management, password policies, and lockout automatically.

# Running the App

1. Run `dotnet run`.
2. Access `https://localhost:5001` (port may vary).
3. Register a user, then log in to access the protected home page.

# Next Steps

- Add email confirmation or password reset (built into Identity).
- Customize password requirements in `Program.cs`.
- Add role-based authorization for admin features.
- Enable CSRF protection (included by default with form tags).
- Consider a UI framework like Bootstrap for better styling.

This setup is faster and more secure than the basic login system, leveraging ASP.NET Core Identity’s robust features and EF Core for persistence. Let me know if you need further customization or have questions!
