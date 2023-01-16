#region using

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Certificate;
using SecureAPI.Extensions;
using SecureAPI.Interfaces;
using SecureAPI.Services;
using System.Threading.Tasks;
using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
using System.Text;
using System.IO;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using System.Net;

#endregion

namespace SecureAPI
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //services.AddSingleton<CertificateValidation>();                       

            //var rootCert = new X509Certificate2("RootCert.pfx", "1234");
            var bin = AppDomain.CurrentDomain.BaseDirectory.IndexOf("\\bin");
            var path = bin > 0 ? AppDomain.CurrentDomain.BaseDirectory.Substring(0, bin) : AppDomain.CurrentDomain.BaseDirectory;

            //X509Certificate certificate = X509Certificate.CreateFromCertFile(path + "\\cert\\clientcert.pfx");
            X509Certificate2 rootCertFE = new X509Certificate2(Path.Combine(path,"cert\\leonardo11.ddns.net.pfx"), "lavolpe",
              X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.DefaultKeySet);
            X509Certificate2 rootCertBE = new X509Certificate2(Path.Combine(path,"cert\\LEOSERVER.local.pfx"), "lavolpe",
              X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.DefaultKeySet);

            services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
                .AddCertificate(options =>
                {
                    options.AllowedCertificateTypes = CertificateTypes.All; //cambia
                    options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
                    options.CustomTrustStore = new X509Certificate2Collection { rootCertFE, rootCertBE };                    
                    options.RevocationMode = X509RevocationMode.NoCheck;
                    options.Events = new CertificateAuthenticationEvents
                    {
                        OnCertificateValidated = context =>
                        {
                            var validationService = context.HttpContext.RequestServices.GetService<CertificateValidation>();
                            if (validationService.ValidateCertificate(context.ClientCertificate))
                            {
                                context.Success();
                            }
                            else
                            {
                                context.Fail("Wrong certificate");
                                string jsonString = JsonSerializer.Serialize(context.HttpContext);
                                Log.Error(jsonString);
                            }
                            return Task.CompletedTask;
                        },
                        OnAuthenticationFailed = context =>
                        {
                            context.Fail("Invalid certificate");
                            string jsonString = JsonSerializer.Serialize(context.HttpContext);
                            Log.Error(jsonString);
                            return Task.CompletedTask;
                        }
                    };
                })
                .AddCertificateCache(options =>
                {
                    options.CacheSize = 1024;
                    options.CacheEntryExpiration = TimeSpan.FromMinutes(2);
                });

            //.AddCertificate(options =>
            //{
            //    options.AllowedCertificateTypes = CertificateTypes.All;
            //    options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
            //    options.CustomTrustStore = new X509Certificate2Collection { rootCertFE, rootCertBE };
            //    options.RevocationMode = X509RevocationMode.NoCheck;
            //    options.Events = new CertificateAuthenticationEvents
            //    {
            //        OnCertificateValidated = context =>
            //        {
            //            var validationService = context.HttpContext.RequestServices.GetService<CertificateValidationService>();

            //            if (validationService.ValidateCertificate(context.ClientCertificate, "526F9E7F9ECC476A51265198A655C7F1125EF3EA") ||
            //                validationService.ValidateCertificate(context.ClientCertificate, "E5CD20F8793B8AB5EB44848DDCD7C969CAC727D3"))
            //            {
            //                var claims = new[]
            //                {
            //                new Claim(ClaimTypes.NameIdentifier, context.ClientCertificate.Subject, ClaimValueTypes.String, context.Options.ClaimsIssuer),
            //                new Claim(ClaimTypes.Name, context.ClientCertificate.Subject, ClaimValueTypes.String, context.Options.ClaimsIssuer)
            //            };

            //                context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
            //                context.Success();
            //            }
            //            else
            //            {
            //                context.Fail("Invalid certificate.");
            //            }                            

            //            return Task.CompletedTask;
            //        },
            //        OnAuthenticationFailed = context =>
            //        {
            //            context.Fail("invalid cert");
            //            return Task.CompletedTask;
            //        }
            //    };
            //});

            //services.AddCertificateForwarding(options =>
            //{
            //    options.CertificateHeader = "X-ARR-ClientCert";
            //    options.HeaderConverter = (headerValue) =>
            //    {
            //        X509Certificate2 clientCertificate = null;
            //        if (!string.IsNullOrWhiteSpace(headerValue))
            //        {
            //            //byte[] bytes = headerValue.ToByteArray();
            //            byte[] bytes = Encoding.ASCII.GetBytes(headerValue);
            //            clientCertificate = new X509Certificate2(bytes);
            //        }
            //        return clientCertificate;
            //    };
            //});

            //services.AddTransient<CertificateValidation>();

            services.ConfigureJWT(Configuration);
            services.AddControllers();

            services.AddScoped<Interfaces.IAuthenticationService, Services.AuthenticationService>();            

            //services.AddCertificateManager(); //build self-signed certificates
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }            

            app.UseHttpsRedirection();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            //if (!env.IsDevelopment())
            //{
            //app.UseCertificateForwarding();

            app.UseSerilogRequestLogging();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers(); //.RequireAuthorization(); No o abilita authorize in automatico su tutti i controller
            });
            //}
            //else
            //{                
            //    app.UseEndpoints(endpoints =>
            //    {
            //        endpoints.MapControllers();
            //    });
            //}
        }
    }
}
