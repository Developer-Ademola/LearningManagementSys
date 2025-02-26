using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace LearningManagementSys.Models
{
    public class ResetPasswordRequest
    {
        [JsonProperty("email")]
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        public string Email { get; set; }

        [JsonProperty("token")]
        [Required(ErrorMessage = "Reset token is required.")]
        public string Token { get; set; }

        [JsonProperty("newPassword")]
        [Required(ErrorMessage = "New password is required.")]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters.")]
        public string NewPassword { get; set; }

        [JsonProperty("confirmPassword")]
        [Required(ErrorMessage = "Confirm password is required.")]
        [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }
    }
}
