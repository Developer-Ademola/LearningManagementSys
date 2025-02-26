using FluentValidation;
using LearningManagementSys.Models;

namespace LearningManagementSys.Validators
{
    public class AppUserValidator : AbstractValidator<AppUser>
    {
        public AppUserValidator()
        {
            RuleFor(user => user.FullName)
                .NotEmpty().WithMessage("Full Name is required.");

            RuleFor(user => user.Email)
                .NotEmpty().WithMessage("Email is required.")
                .EmailAddress().WithMessage("Invalid email format.");

            RuleFor(user => user.PhoneNumber)
                .NotEmpty().WithMessage("Phone number is required.")
                .Matches(@"^\d{10,15}$").WithMessage("Phone number must be between 10-15 digits.");

            RuleFor(user => user.PasswordHash)
                .NotEmpty().WithMessage("Password is required.")
                .MinimumLength(6).WithMessage("Password must be at least 6 characters long.");
        }
    }
}
