# Project Setup

1. Create a new ASP.NET Core MVC project:

```bash
dotnet new mvc -n BasicAuthApp
cd BasicAuthApp
```

2. Add required NuGet packages:

```bash
dotnet add package Microsoft.AspNetCore.Authentication.Cookies
```

# Implementation

## 1. User Model and Storage

Create `Models/User.cs` for user data and in-memory storage (for simplicity; replace with a database for production).

```csharp
using System.Security.Cryptography;
using System.Text;

namespace BasicAuthApp.Models
{
    public class User
    {
        public string Username { get; set; }
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
    }

    public static class UserStore
    {
        private static readonly List<User> Users = new List<User>();

        public static User FindUser(string username) => Users.FirstOrDefault(u => u.Username == username);

        public static void AddUser(string username, string password)
        {
            var (hash, salt) = HashPassword(password);
            Users.Add(new User { Username = username, PasswordHash = hash, PasswordSalt = salt });
        }

        private static (byte[] hash, byte[] salt) HashPassword(string password)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, 16, 100000, HashAlgorithmName.SHA256);
            return (pbkdf2.GetBytes(32), pbkdf2.Salt);
        }

        public static bool VerifyPassword(string password, byte[] storedHash, byte[] storedSalt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, storedSalt, 100000, HashAlgorithmName.SHA256);
            var hash = pbkdf2.GetBytes(32);
            return CryptographicOperations.FixedTimeEquals(hash, storedHash);
        }
    }
}
```

## 2. Configure Authentication

Update `Program.cs` to enable cookie authentication.

```csharp
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
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

## 3. Account Controller

Create `Controllers/AccountController.cs` for login, registration, and logout.

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using BasicAuthApp.Models;

namespace BasicAuthApp.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Login() => View();

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            var user = UserStore.FindUser(username);
            if (user != null && UserStore.VerifyPassword(password, user.PasswordHash, user.PasswordSalt))
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username)
                };
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                return RedirectToAction("Index", "Home");
            }
            ViewBag.Error = "Invalid credentials";
            return View();
        }

        [HttpGet]
        public IActionResult Register() => View();

        [HttpPost]
        public IActionResult Register(string username, string password)
        {
            if (UserStore.FindUser(username) == null)
            {
                UserStore.AddUser(username, password);
                return RedirectToAction("Login");
            }
            ViewBag.Error = "Username already exists";
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login");
        }
    }
}
```

## 4. Views

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

Create `Views/Account/Register.cshtml`:

```html
@model dynamic
<h2>Register</h2>
@if (ViewBag.Error != null) { <p style="color:red">@ViewBag.Error</p> }
<form method="post">
    <label>Username</label><input type="text" name="username" required /><br />
    <label>Password</label><input type="password" name="password" required /><br />
    <button type="submit">Register</button>
    <a href="@Url.Action("Login")">Back to Login</a>
</form>
```

## 5. Protected Page

Update `Controllers/HomeController.cs` to protect the Index action:

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BasicAuthApp.Controllers
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

- **Password Hashing**: Uses PBKDF2 with SHA256, 100,000 iterations, and 16-byte salt for secure password storage.
- **Cookie Auth**: Secure cookies with a 1-hour expiration; adjust `ExpireTimeSpan` as needed.
- **In-Memory Storage**: For simplicity; replace with a database (e.g., SQLite/EF Core) for persistence.
- **HTTPS**: Enforced via `UseHttpsRedirection` to secure data in transit.
- **Minimal Dependencies**: Only uses `Microsoft.AspNetCore.Authentication.Cookies`.

# Running the App

1. Run `dotnet run`.
2. Access `https://localhost:5001` (port may vary).
3. Register a user, then log in to access the protected home page.
