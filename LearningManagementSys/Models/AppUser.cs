using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace LearningManagementSys.Models
{
    public class AppUser
    {
        [JsonProperty("id")]
        public string Id { get; private set; } = Guid.NewGuid().ToString(); // ✅ Auto-generate ID

        [JsonProperty("fullName")]
        [Required(ErrorMessage = "Full Name is required.")]
        public string FullName { get; set; }

        [JsonProperty("email")]
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        public string Email { get; set; }

        [JsonProperty("phoneNumber")]
        [Required(ErrorMessage = "Phone number is required.")]
        [RegularExpression(@"^\d{10,15}$", ErrorMessage = "Phone number must be between 10-15 digits.")]
        public string PhoneNumber { get; set; }

        [JsonProperty("passwordHash")]
        [Required(ErrorMessage = "Password is required.")]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long.")]
        public string PasswordHash { get; set; }

        [JsonProperty("isVerified")]
        public bool IsVerified { get; private set; } = false; // ✅ Hidden from API responses

        public void VerifyUser()
        {
            IsVerified = true;
        }
    }
}
