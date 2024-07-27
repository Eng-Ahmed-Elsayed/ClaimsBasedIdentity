using ClaimsBasedIdentity.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace ClaimsBasedIdentity.ViewModels
{
    public class EditUserViewModel
    {
        public string UserId { get; set; }
        public string Email { get; set; }
        public List<IdentityRole> Roles { get; set; }
        public IList<string> UserRoles { get; set; }
        public IList<Claim> UserClaims { get; set; }
        public Dictionary<string, bool> RoleSelections { get; set; } = new Dictionary<string, bool>();
        public Dictionary<string, bool> ClaimSelections { get; set; } = new Dictionary<string, bool>();
        public List<ClaimConfig> AvailableClaims { get; set; } = new List<ClaimConfig>();
    }
}
