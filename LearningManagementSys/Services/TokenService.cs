using LearningManagementSys.Models;

namespace LearningManagementSys.Services
{
    public class TokenService
    {
        private static List<VerificationToken> _tokens = new();

        public string GenerateToken(string email)
        {
            var token = new Random().Next(100000, 999999).ToString();
            _tokens.Add(new VerificationToken { Email = email, Token = token, ExpiryTime = DateTime.UtcNow.AddMinutes(10) });
            return token;
        }

        public bool ValidateToken(string email, string token)
        {
            var validToken = _tokens.FirstOrDefault(t => t.Email == email && t.Token == token && t.ExpiryTime > DateTime.UtcNow);
            return validToken != null;
        }

        public void RemoveToken(string email)
        {
            _tokens.RemoveAll(t => t.Email == email);
        }
    }
}
