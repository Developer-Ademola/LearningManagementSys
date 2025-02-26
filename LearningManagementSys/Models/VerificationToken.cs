using Newtonsoft.Json;

namespace LearningManagementSys.Models
{
    public class VerificationToken
    {
        [JsonProperty("email")]
        public string Email { get; set; }

        [JsonProperty("token")]
        public string Token { get; set; }

        [JsonIgnore] // ✅ Hide ExpiryTime in API responses
        public DateTime ExpiryTime { get; set; }
    }
}
