using ClaimsBasedIdentity.Models;
using ClaimsBasedIdentity.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace ClaimsBasedIdentity.Controllers
{
    //[Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly List<ClaimConfig> _availableClaims;
        public AdminController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IOptions<List<ClaimConfig>> availableClaims,
            SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _availableClaims = availableClaims.Value;
            _signInManager = signInManager;
        }

        [Authorize(Policy = "RetrivePolicy")]
        public IActionResult Index()
        {
            var users = _userManager.Users.ToList();
            return View(users);
        }

        [Authorize(Policy = "UpdatePolicy")]
        public async Task<IActionResult> Edit(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();

            var userRoles = await _userManager.GetRolesAsync(user);
            var allRoles = _roleManager.Roles.ToList();
            var userClaims = await _userManager.GetClaimsAsync(user);

            List<ClaimConfig> availableClaims = _availableClaims
            .Where(claim =>
            !userClaims.Any(config => config.Type == claim.Type && config.Value == claim.Value))
            .ToList();
            var model = new EditUserViewModel
            {
                UserId = user.Id,
                Email = user.Email,
                Roles = allRoles,
                UserRoles = userRoles,
                UserClaims = await _userManager.GetClaimsAsync(user),
                RoleSelections = allRoles.ToDictionary(role => role.Name, role => userRoles.Contains(role.Name)),
                ClaimSelections = userClaims.ToDictionary(claim => claim.Type + ":" + claim.Value, claim => true),
                AvailableClaims = availableClaims
            };
            return View(model);
        }

        [Authorize(Policy = "UpdatePolicy")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(EditUserViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null) return NotFound();

            // Process roles
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in _roleManager.Roles.ToList())
            {
                if (model.RoleSelections.ContainsKey(role.Name) && model.RoleSelections[role.Name])
                {
                    if (!userRoles.Contains(role.Name))
                    {
                        await _userManager.AddToRoleAsync(user, role.Name);
                    }
                }
                else
                {
                    if (userRoles.Contains(role.Name))
                    {
                        await _userManager.RemoveFromRoleAsync(user, role.Name);
                    }
                }
            }

            // Process claims
            var userClaims = await _userManager.GetClaimsAsync(user);
            var selectedClaims = model.ClaimSelections
                .Where(c => c.Value)
                .Select(c => new Claim(c.Key.Split(' ')[0], c.Key.Split(' ')[4]))
                .ToList();

            foreach (var claim in selectedClaims)
            {
                if (!userClaims.Any(c => c.Type == claim.Type && c.Value == claim.Value))
                {
                    await _userManager.AddClaimAsync(user, claim);
                }
            }

            foreach (var claim in userClaims)
            {
                if (!selectedClaims.Any(c => c.Type == claim.Type && c.Value == claim.Value))
                {
                    await _userManager.RemoveClaimAsync(user, claim);
                }
            }
            await _signInManager.RefreshSignInAsync(user);
            return RedirectToAction(nameof(Index));
        }
    }
}
