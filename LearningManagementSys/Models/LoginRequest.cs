using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace LearningManagementSys.Models
{
    public class LoginRequest
    {
        [JsonProperty("email")]
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        public string Email { get; set; }

        [JsonProperty("password")]
        [Required(ErrorMessage = "Password is required.")]
        public string Password { get; set; }
    }
}
