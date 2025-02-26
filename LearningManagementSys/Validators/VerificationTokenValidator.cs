using FluentValidation;
using LearningManagementSys.Models;

namespace LearningManagementSys.Validators
{
    public class VerificationTokenValidator : AbstractValidator<VerificationToken>
    {
        public VerificationTokenValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("Email is required.")
                .EmailAddress().WithMessage("Invalid email format.");

            RuleFor(x => x.Token)
                .NotEmpty().WithMessage("Verification token is required.");
        }
    }
}
