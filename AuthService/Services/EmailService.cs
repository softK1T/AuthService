using AuthService.Models;

namespace AuthService.Services
{
    public class EmailService: IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, HttpClient httpClient, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _httpClient = httpClient;
            _logger = logger;
        }
        public async Task SendConfirmationEmailAsync(string email, string confirmationLink)
        {
            var mailServiceUrl = Environment.GetEnvironmentVariable("MAIL_SERVICE_URL") ??
                                _configuration["MailService:BaseUrl"];

            if (string.IsNullOrEmpty(mailServiceUrl))
            {
                throw new InvalidOperationException("Mail service URL is not configured");
            }

            string htmlBody = $@"
                <html>
                <body>
                    <h2>Thank you for registering!</h2>
                    <p>Please confirm your account by clicking this link: <a href='{confirmationLink}'>{confirmationLink}</a></p>
                </body>
                </html>";

            var mailRequest = new MailRequest
            {
                ToEmail = email,
                Subject = "Confirm your email",
                Body = htmlBody
            };

            _httpClient.BaseAddress = new Uri(mailServiceUrl);
            _logger.LogInformation("Sending email confirmation request to {Url}", mailServiceUrl);

            var formContent = new MultipartFormDataContent();
            formContent.Add(new StringContent(mailRequest.ToEmail), "ToEmail");
            formContent.Add(new StringContent(mailRequest.Subject), "Subject");
            formContent.Add(new StringContent(mailRequest.Body), "Body");

            var response = await _httpClient.PostAsync("/api/Email/send", formContent);

            if (!response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("Mail service returned error: {StatusCode}, {Content}",
                    response.StatusCode, responseContent);
                throw new HttpRequestException($"Mail service returned {response.StatusCode}");
            }
        }
    }
}
