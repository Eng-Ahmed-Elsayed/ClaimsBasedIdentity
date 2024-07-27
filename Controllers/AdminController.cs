using ClaimsBasedIdentity.Models;
using ClaimsBasedIdentity.ViewModels;
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
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly List<ClaimConfig> _availableClaims;
        public AdminController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IOptions<List<ClaimConfig>> availableClaims)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _availableClaims = availableClaims.Value;
        }

        public IActionResult Index()
        {
            var users = _userManager.Users.ToList();
            return View(users);
        }

        public async Task<IActionResult> Edit(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();

            var userRoles = await _userManager.GetRolesAsync(user);
            var userClaims = await _userManager.GetClaimsAsync(user);
            var allRoles = _roleManager.Roles.ToList();

            var availableClaims = new List<Claim>
            {
                new Claim("ClaimType1", "ClaimValue1"),
                new Claim("ClaimType2", "ClaimValue2"),
                // Add more predefined claims or dynamically fetch them
            };

            var model = new EditUserViewModel
            {
                UserId = user.Id,
                Email = user.Email,
                Roles = allRoles,
                UserRoles = userRoles,
                UserClaims = await _userManager.GetClaimsAsync(user),
                RoleSelections = allRoles.ToDictionary(role => role.Name, role => userRoles.Contains(role.Name)),
                ClaimSelections = userClaims.ToDictionary(claim => claim.Type + ":" + claim.Value, claim => true),
                AvailableClaims = _availableClaims
            };
            return View(model);
        }

        [HttpPost]
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
                .Select(c => new Claim(c.Key.Split(':')[0], c.Key.Split(':')[1]))
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

            return RedirectToAction(nameof(Index));
        }
    }
}
