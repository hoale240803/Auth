using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CustomJWTWith2FA.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy = "2FARequired")]
    public class AssetsController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetAssets()
        {
            return Ok($"Assets viewed by {User.Identity.Name}");
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult CreateAsset()
        {
            return Ok($"Asset created by {User.Identity.Name}");
        }
    }
}