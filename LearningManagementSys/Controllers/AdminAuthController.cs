using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LearningManagementSys.Controllers
{
    [Route("api/admin/auth")]
    [ApiController]
    public class AdminAuthController : ControllerBase
    {
        private const string AdminUsername = "admin123";
        private const string AdminPassword = "Password321";
        private readonly IConfiguration _configuration;

        public AdminAuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] AdminLoginRequest request)
        {
            if (request.Username != AdminUsername || request.Password != AdminPassword)
                return Unauthorized("Invalid admin credentials.");

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, request.Username),
                    new Claim(ClaimTypes.Role, "Admin") // ✅ Add Admin role to JWT
                }),
                Expires = DateTime.UtcNow.AddHours(2), // Token expires in 2 hours
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return Ok(new { Token = tokenString });
        }
    }

    public class AdminLoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
