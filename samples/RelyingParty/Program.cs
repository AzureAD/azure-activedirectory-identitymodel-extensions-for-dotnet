//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using WcfUtilities;

// http.sys needs to be setup with something like the following where certhash == "the thumprint for the RelyingParty"
// netsh http add sslcert ipport=127.0.0.1:443 certhash=826068f64be4baad2b2bf49795fe6ac8b0020a8d appid={00112233-4455-6677-8899-AABBCCDDEEFF}

namespace RelyingParty
{
    class Program
    {
        static string _saml11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
        static string _saml20 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

        static void Main(string[] args)
        {
            // bypasses certificate validation
            ServicePointManager.ServerCertificateValidationCallback = ValidateServerCertificate;

            IssuerBaseAddress = "Put base address to ADFS here";
            ServiceAddress = "https://127.0.0.1:443/IssuedTokenUsingTls";
            ServiceCert = CertificateUtilities.GetCertificate(StoreName.My, StoreLocation.LocalMachine, X509FindType.FindByThumbprint, "826068f64be4baad2b2bf49795fe6ac8b0020a8d");
            UpnIdentity = "Put UpnIdentity here";
            UsernameMixed = "trust/13/usernamemixed";
            WindowsTransport = "trust/13/windowsTransport";

            var issuerBinding = IssuerBindingUsername();
            var serviceBinding = ServiceBinding(false, SecurityKeyType.SymmetricKey, _saml20, IssuerEndpointAddress, issuerBinding, WSFederationHttpSecurityMode.TransportWithMessageCredential);

            // service host
            var serviceHost = new ServiceHost(typeof(RequestReply), new Uri(ServiceAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReply), serviceBinding, ServiceAddress);
            serviceHost.Credentials.ServiceCertificate.Certificate = ServiceCert;

            // setting UseIdentityConfiguration = true is what allows Saml2 tokens, but default only SAML1 tokens are allowed.
            // bypass all checks of inbound token
            serviceHost.Credentials.UseIdentityConfiguration = true;
            serviceHost.Credentials.IdentityConfiguration.AudienceRestriction.AudienceMode = System.IdentityModel.Selectors.AudienceUriMode.Never;
            serviceHost.Credentials.IdentityConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;
            serviceHost.Credentials.IdentityConfiguration.IssuerNameRegistry = new CustomIssuerNameRegistry("authority");
            serviceHost.Open();

            BindingUtilities.DisplayBindingInfoToConsole(serviceHost);
            Console.WriteLine("Press any key to close.");
            Console.ReadKey();
        }

        public static Binding ServiceBinding(bool establishSecurityContext, SecurityKeyType issuedKeyType, string issuedTokenType, EndpointAddress issuerAddress, Binding issuerBinding, WSFederationHttpSecurityMode mode)
        {
            return BindingUtilities.SetMaxTimeout(
                new WS2007FederationHttpBinding
                {
                    Security = new WSFederationHttpSecurity
                    {
                        Message = new FederatedMessageSecurityOverHttp
                        {
                            EstablishSecurityContext = establishSecurityContext,
                            IssuedKeyType = issuedKeyType,
                            IssuedTokenType = issuedTokenType,
                            IssuerAddress = issuerAddress,
                            IssuerBinding = issuerBinding
                        },
                        Mode = mode
                    }
                });
        }

        public static Binding IssuerBindingUsername()
        {
            IssuerEndpointAddress = new EndpointAddress(IssuerBaseAddress + UsernameMixed);

            return BindingUtilities.SetMaxTimeout(
                new WS2007HttpBinding
                {
                    Security = new WSHttpSecurity
                    {
                        Message = new NonDualMessageSecurityOverHttp
                        {
                            EstablishSecurityContext = false,
                            ClientCredentialType = MessageCredentialType.UserName
                        },
                        Mode = SecurityMode.TransportWithMessageCredential
                    },
                });
        }

        public static Binding IssuerBindingWindowsTransport()
        {
            IssuerEndpointAddress = new EndpointAddress(new Uri(IssuerBaseAddress + WindowsTransport), EndpointIdentity.CreateUpnIdentity(UpnIdentity), new AddressHeaderCollection());

            return BindingUtilities.SetMaxTimeout(
                new WS2007HttpBinding
                {
                    Security = new WSHttpSecurity
                    {
                        Transport = new HttpTransportSecurity
                        {
                            ClientCredentialType = HttpClientCredentialType.Windows
                        },
                        Mode = SecurityMode.Transport
                    },
                });
        }

        public static EndpointAddress IssuerEndpointAddress { get; set; }

        public static string IssuerBaseAddress { get; set; }

        public static X509Certificate2 ServiceCert { get; set; }

        public static string ServiceAddress { get; set; }

        public static string WindowsTransport { get; set; }

        public static string UpnIdentity { get; set; }

        public static string UsernameMixed { get; set; }

        static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }

    class CustomIssuerNameRegistry : IssuerNameRegistry
    {
        string _issuer;
        public CustomIssuerNameRegistry(string issuer)
        {
            _issuer = issuer;
        }

        public override string GetIssuerName(SecurityToken securityToken)
        {
            return _issuer;
        }
    }

    [ServiceContract]
    interface IRequestReply
    {
        [OperationContract(Name ="SendString")]
        string SendString(string message);
    }

    [ServiceBehavior]
    class RequestReply : IRequestReply
    {
        static int numberOfRequests = 1;

        [OperationBehavior]
        public string SendString(string message)
        {
            string outbound = string.Format($"Service received: '{message}'.");
            Console.WriteLine($"Service received: '{message}' + requestNumber: '{numberOfRequests++}'.");
            Console.WriteLine($"Service returning: '{outbound}'.");
            return outbound;
        }
    }
}
