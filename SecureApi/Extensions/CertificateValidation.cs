using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SecureAPI.Extensions
{
    //https://www.c-sharpcorner.com/article/using-certificates-for-api-authentication-in-net-5/

    public class CertificateValidationService
    {
        public bool ValidateCertificate(X509Certificate2 clientCertificate, string thumbprintToChek) =>
            clientCertificate.Thumbprint.Equals(thumbprintToChek);
    }
    public class CertificateValidation
    {
        public bool ValidateCertificate(X509Certificate2 clientCertificate)
        {
            string[] allowedThumbprints = {
                "E5CD20F8793B8AB5EB44848DDCD7C969CAC727D3", //CERT FE 
                "526F9E7F9ECC476A51265198A655C7F1125EF3EA"  //CERT BE
            };
            //togliere
            Console.WriteLine(clientCertificate.Thumbprint);
            if (allowedThumbprints.Contains(clientCertificate.Thumbprint))
            {                
                return true;
            }
            return false;
        }
    }

    public class MyCertificateValidationService
    {
        private readonly ILogger<MyCertificateValidationService> _logger;

        public MyCertificateValidationService(ILogger<MyCertificateValidationService> logger)
        {
            _logger = logger;
        }

        public bool ValidateCertificate(X509Certificate2 clientCertificate)
        {
            return CheckIfThumbprintIsValid(clientCertificate);
        }

        private bool CheckIfThumbprintIsValid(X509Certificate2 clientCertificate)
        {
            var listOfValidThumbprints = new List<string>
        {
            // add thumbprints of your allowed clients
            "E5CD20F8793B8AB5EB44848DDCD7C969CAC727D3", //CERT FE 
            "526F9E7F9ECC476A51265198A655C7F1125EF3EA"  //CERT BE
        };

            if (listOfValidThumbprints.Contains(clientCertificate.Thumbprint))
            {
                _logger.LogInformation($"Custom auth-success for certificate  {clientCertificate.FriendlyName} {clientCertificate.Thumbprint}");

                return true;
            }

            _logger.LogWarning($"auth failed for certificate  {clientCertificate.FriendlyName} {clientCertificate.Thumbprint}");

            return false;
        }
    }
}
