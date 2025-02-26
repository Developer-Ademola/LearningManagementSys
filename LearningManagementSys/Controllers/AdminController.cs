using LearningManagementSys.Data;
using Microsoft.AspNetCore.Mvc;

namespace LearningManagementSys.Controllers
{
    [Route("api/admin")]
    [ApiController]
    // [Authorize(Roles = "Admin")] // ✅ Protect all admin endpoints with JWT authentication
    public class AdminController : ControllerBase
    {
        private readonly CosmosDbService _cosmosDbService;

        public AdminController(CosmosDbService cosmosDbService)
        {
            _cosmosDbService = cosmosDbService;
        }

        [HttpGet("all-users")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _cosmosDbService.GetAllUsersAsync();
            return Ok(users);
        }

        [HttpGet("unverified-users")]
        public async Task<IActionResult> GetUnverifiedUsers()
        {
            var users = await _cosmosDbService.GetAllUsersAsync();
            var unverifiedUsers = users.Where(u => !u.IsVerified).ToList();
            return Ok(unverifiedUsers);
        }

        [HttpGet("filter-by-email")]
        public async Task<IActionResult> GetUserByEmail([FromQuery] string email)
        {
            var user = await _cosmosDbService.GetUserByEmailAsync(email);
            if (user == null)
                return NotFound("User not found.");

            return Ok(user);
        }

        [HttpGet("filter-by-name")]
        public async Task<IActionResult> GetUsersByName([FromQuery] string name)
        {
            var users = await _cosmosDbService.GetAllUsersAsync();
            var filteredUsers = users.Where(u => u.FullName.ToLower().Contains(name.ToLower())).ToList();

            if (!filteredUsers.Any())
                return NotFound("No users found with this name.");

            return Ok(filteredUsers);
        }
    }
}
