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