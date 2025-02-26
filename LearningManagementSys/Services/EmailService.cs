using Azure.Communication.Email;
using System.Net.Mail;

namespace LearningManagementSys.Services
{
    public class EmailService
    {
        private readonly EmailClient _emailClient;
        private readonly string _senderEmail;

        public EmailService(IConfiguration configuration)
        {
            _emailClient = new EmailClient(configuration["AzureCommunication:ConnectionString"]);
            _senderEmail = configuration["AzureCommunication:Sender"];
        }

        public async Task SendEmailAsync(string recipient, string subject, string body)
        {
            var emailContent = new EmailContent(subject)
            {
                Html = body
            };
            var emailRecipients = new EmailRecipients(new List<EmailAddress> { new EmailAddress(recipient) });

            var emailMessage = new EmailMessage(_senderEmail, emailRecipients, emailContent);

            EmailSendOperation emailSendOperation = await _emailClient.SendAsync(Azure.WaitUntil.Completed, emailMessage);

            System.Console.WriteLine($"Email sent successfully! Operation ID: {emailSendOperation.Id}");
        }
    }
}
