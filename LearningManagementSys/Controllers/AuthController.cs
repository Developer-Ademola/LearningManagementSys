using LearningManagementSys.Data;
using LearningManagementSys.Models;
using LearningManagementSys.Services;
using Microsoft.AspNetCore.Mvc;

namespace LearningManagementSys.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly CosmosDbService _cosmosDbService;
        private readonly EmailService _emailService;
        private readonly TokenService _tokenService;

        public AuthController(CosmosDbService cosmosDbService, EmailService emailService, TokenService tokenService)
        {
            _cosmosDbService = cosmosDbService;
            _emailService = emailService;
            _tokenService = tokenService;
        }

         [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] AppUser user)
        {
            if (await _cosmosDbService.GetUserByEmailAsync(user.Email) != null)
                return BadRequest("Email already registered.");

           user.VerifyUser(); // Directly mark user as verified
                await _cosmosDbService.AddUserAsync(user);

            return Ok(new { Message = "Registration successful." });
        }
       
       [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
                var user = await _cosmosDbService.GetUserByEmailAsync(request.Email);
                    if (user == null || user.PasswordHash != request.Password)
                        return Unauthorized("Invalid credentials.");

                string token = _tokenService.GenerateToken(user.Email); // Direct JWT token return

            return Ok(new { Message = "Login successful." });
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            var user = await _cosmosDbService.GetUserByEmailAsync(request.Email);
            if (user == null)
                return NotFound("User not found.");

            string token = _tokenService.GenerateToken(user.Email);
            await _emailService.SendEmailAsync(user.Email, "Password Reset Token", $"Your reset token is {token}");

            return Ok("Enter the token to reset your password.");
        }

        [HttpPost("verify-reset-token")]
        public async Task<IActionResult> VerifyResetToken([FromBody] VerificationToken request)
        {
            if (!_tokenService.ValidateToken(request.Email, request.Token))
                return BadRequest("Invalid or expired token.");

            return Ok("Token is valid. You can now reset your password.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var user = await _cosmosDbService.GetUserByEmailAsync(request.Email);
            if (user == null)
                return NotFound("User not found.");

            if (!_tokenService.ValidateToken(request.Email, request.Token))
                return BadRequest("Invalid or expired token.");

            if (request.NewPassword != request.ConfirmPassword)
                return BadRequest("Passwords do not match.");

            user.PasswordHash = request.NewPassword;
            await _cosmosDbService.UpdateUserAsync(user);
            _tokenService.RemoveToken(request.Email);

            await _emailService.SendEmailAsync(user.Email, "Password Reset Successful", "Your password has been successfully reset.");
            return Ok("Password reset successful.");
        }
    }
}



        // [HttpPost("register")]
        // public async Task<IActionResult> Register([FromBody] AppUser user)
        // {
        //     if (await _cosmosDbService.GetUserByEmailAsync(user.Email) != null)
        //         return BadRequest("Email already registered.");

        //     await _cosmosDbService.AddUserAsync(user); // ✅ No need to manually set id, it's auto-generated in AppUser.cs

        //     string token = _tokenService.GenerateToken(user.Email);
        //     await _emailService.SendEmailAsync(user.Email, "Email Verification", $"Your verification token is {token}");

        //     return Ok(new { Message = "Verification email sent." });
        // }

        // [HttpPost("verify")]
        // public async Task<IActionResult> Verify([FromBody] VerificationToken request)
        // {
        //     if (!_tokenService.ValidateToken(request.Email, request.Token))
        //         return BadRequest("Invalid or expired token.");

        //     var user = await _cosmosDbService.GetUserByEmailAsync(request.Email);
        //     if (user == null) return NotFound("User not found."); // ✅ This should no longer happen

        //     user.VerifyUser(); // ✅ Mark user as verified
        //     await _cosmosDbService.UpdateUserAsync(user);
        //     _tokenService.RemoveToken(request.Email);

        //     await _emailService.SendEmailAsync(user.Email, "Welcome!", "Registration successful.");
        //     return Ok("Registration complete.");
        // }

        // [HttpPost("login")]
        // public async Task<IActionResult> Login([FromBody] LoginRequest request)
        // {
        //     var user = await _cosmosDbService.GetUserByEmailAsync(request.Email);
        //     if (user == null || user.PasswordHash != request.Password)
        //         return Unauthorized("Invalid credentials.");

        //     string token = _tokenService.GenerateToken(user.Email);
        //     await _emailService.SendEmailAsync(user.Email, "Login Verification", $"Your login token is {token}");

        //     return Ok("Enter the token to complete login.");
        // }

        // [HttpPost("verify-login")]
        // public async Task<IActionResult> VerifyLogin([FromBody] VerificationToken request)
        // {
        //     if (!_tokenService.ValidateToken(request.Email, request.Token))
        //         return BadRequest("Invalid or expired token.");

        //     _tokenService.RemoveToken(request.Email);
        //     return Ok("Login successful.");
        // }

