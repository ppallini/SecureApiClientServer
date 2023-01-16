using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureAPIClient;
using Serilog;
using Serilog.Events;

namespace FrontEnd.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;

            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Verbose)
                .MinimumLevel.Verbose()
                .Enrich.FromLogContext()
                .WriteTo.Console()
                .WriteTo.File("../log/clientLogs.txt")
                .CreateLogger();
        }

        public async Task OnGetAsync()
        {
            var userName = "TonySilva";
            var password = "abc123";

            Log.Information("Starting web client");

            var tokenData = await AuthenticationClient.LoginAsync(userName, password);
            if (!tokenData.LoginSuccessful)
            {
                Console.WriteLine("Invalid login.");
            }
            else
            {
            }
        }
    }
}