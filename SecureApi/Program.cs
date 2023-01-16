#region using

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;

#endregion

namespace SecureAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Verbose)
                .MinimumLevel.Verbose()
                .Enrich.FromLogContext()
                .WriteTo.Console()
                .WriteTo.File("../log/serverLogs.txt")
                .CreateLogger();

            try
            {
                Log.Information("Starting web host");
                var builder = CreateHostBuilder(args).Build();
                builder.Run();

            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Host terminated unexpectedly");
            }
            finally
            {
                Log.CloseAndFlush();
            }


        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    var bin = AppDomain.CurrentDomain.BaseDirectory.IndexOf("\\bin");
                    var path = bin > 0 ? AppDomain.CurrentDomain.BaseDirectory.Substring(0, bin) : AppDomain.CurrentDomain.BaseDirectory;                   
                    var certBE = new X509Certificate2(Path.Combine(path, "cert\\LEOSERVER.local.pfx"), "lavolpe");                    

#pragma warning disable CS0618 // Il tipo o il membro è obsoleto

                    webBuilder.ConfigureKestrel(kso =>
                    {
                        kso.ConfigureHttpsDefaults(cao =>
                        {                           
                            cao.ServerCertificate = certBE; //un solo certificato possibile
                            cao.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                            cao.AllowAnyClientCertificate();
                            cao.CheckCertificateRevocation = false;
                            cao.ClientCertificateValidation = (cert, chain, policyErrors) =>
                            {
                                // Certificate validation logic here
                                // Return true if the certificate is valid or false if it is invalid
                                string jsonString = JsonSerializer.Serialize(policyErrors);
                                Log.Error(jsonString);
                                return true;
                            };
                        });
                    }).UseSerilog((hostingContext, loggerConfiguration) => loggerConfiguration
                                   .ReadFrom.Configuration(hostingContext.Configuration)
                                   .MinimumLevel.Override("Microsoft", LogEventLevel.Verbose)
                                   .MinimumLevel.Verbose()
                                   .Enrich.FromLogContext()
                                   //.WriteTo.File(@"..\log\serverLogs.txt")
                                   .WriteTo.Console(theme: AnsiConsoleTheme.Code));

                    webBuilder.UseIISIntegration()
                              .UseIIS()
                              .UseStartup<Startup>()
                              .UseSerilog((hostingContext, loggerConfiguration) => loggerConfiguration
                                   .ReadFrom.Configuration(hostingContext.Configuration)
                                   .MinimumLevel.Override("Microsoft", LogEventLevel.Verbose)
                                   .MinimumLevel.Verbose()
                                   .Enrich.FromLogContext()
                                   //.WriteTo.File(@"..\log\serverLogs.txt")
                                   .WriteTo.Console(theme: AnsiConsoleTheme.Code));
                    
#pragma warning restore CS0618 // Il tipo o il membro è obsoleto

                });
    }
}
