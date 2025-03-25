namespace AuthService.Services
{
    public interface IEmailService
    {
        Task SendConfirmationEmailAsync(string email, string confirmationLink);
    }
}
