using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

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