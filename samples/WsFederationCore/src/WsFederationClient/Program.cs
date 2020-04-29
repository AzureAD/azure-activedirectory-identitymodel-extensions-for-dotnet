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
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Federation;
using System.ServiceModel.Security;
using WcfUtilities;

#pragma warning disable CS3003 // Binding, EndpointAddress not CLS-compliant
namespace WsFederationClient
{
    class Program
    {
        static string _saml11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
        static string _saml20 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

        static void Main(string[] args)
        {
            IssuerBaseAddress = @"Put base address to ADFS here";
            Password = "Put Password here";
            ServiceAddress = "https://127.0.0.1:443/IssuedTokenUsingTls";
            ServiceCert = CertificateUtilities.GetCertificate(StoreName.My, StoreLocation.LocalMachine, X509FindType.FindByThumbprint, "826068f64be4baad2b2bf49795fe6ac8b0020a8d");
            UpnIdentity = "Put UpnIdentity here";
            Username = "Put Username here";
            UsernameMixed = "trust/13/usernamemixed";
            WindowsTransport = "trust/13/windowstransport";

            bool username = true;
            Binding serviceBinding = null;
            if (username)
                serviceBinding = ServiceBinding(
                    false,
                    SecurityKeyType.SymmetricKey,
                    _saml20,
                    new EndpointAddress(IssuerBaseAddress + UsernameMixed),
                    IssuerBindingUsername(),
                    SecurityMode.TransportWithMessageCredential);
            else
                serviceBinding = ServiceBinding(
                    false,
                    SecurityKeyType.SymmetricKey,
                    _saml20,
                    // currently we are unable to set the UPN or SPN this will only work with default identity
                    // it hasn't been tested yet.
                    new EndpointAddress(new Uri(IssuerBaseAddress + WindowsTransport)),
                    IssuerBindingWindowsTransport(),
                    SecurityMode.TransportWithMessageCredential);

            var channelFactory = new ChannelFactory<IRequestReply>(serviceBinding, new EndpointAddress(ServiceAddress));
            // TODO - create RelyingParty certificate so this is custom certificate is not needed.

            // this allows to use an untrused certificate for the STS and RelyingParty
            // the validator will be used for the STS and RelyingParty
            // if seperate validation is required, then a WsTrustClientCredentials could be created with its own CertificateValidator passing the outer
            // ClientCredentials as a parameter.
            channelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication
            {
                CertificateValidationMode = X509CertificateValidationMode.Custom,
                CustomCertificateValidator = new CustomCertificateValidator()
            };

            if (username)
            {
                channelFactory.Credentials.UserName.Password = Password;
                channelFactory.Credentials.UserName.UserName = Username;
            }
            else
            {
                channelFactory.Credentials.Windows.ClientCredential = new NetworkCredential();
            }

            Console.WriteLine($"=========================================");
            Console.WriteLine($"WsFederationClient *** CORE ***.");
            Console.WriteLine($"ServiceAddess: '{ServiceAddress}'.");
            Console.WriteLine($"IssuerAddress: '{IssuerAddress}'.");
            Console.WriteLine($"=========================================");
            Console.WriteLine($"");


            var channel = channelFactory.CreateChannel();
            try
            {
                var outboundMessage = "Hello";
                Console.WriteLine($"Channel sending:'{outboundMessage}'.");
                Console.WriteLine($"Channel received: '{channel.SendString(outboundMessage)}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Caught Exception => '{ex}'.");
            }

            Console.WriteLine("Channel sent request, press any key to close.");
            Console.ReadKey();
        }

        public static EndpointAddress EndpointAddress { get; set; }

        public static string IssuerAddress { get; set; }

        public static string IssuerBaseAddress { get; set; }

        public static string Password { get; set;  }

        public static X509Certificate2 ServiceCert { get; set; }

        public static string ServiceAddress { get; set; }

        public static string WindowsTransport { get; set; }

        public static string UpnIdentity { get; set; }

        public static string Username { get; set; }

        public static string UsernameMixed { get; set; }


        public static Binding ServiceBinding(bool establishSecurityContext, SecurityKeyType issuedKeyType, string issuedTokenType, EndpointAddress issuerAddress, Binding issuerBinding, SecurityMode mode)
        {
            return BindingUtilities.SetMaxTimeout(
                new WsFederationHttpBinding(
                    new WsTrustTokenParameters
                    {
                        IssuerAddress = issuerAddress,
                        IssuerBinding = issuerBinding,
                        TokenType = issuedTokenType,
                        KeyType = issuedKeyType
                    }));
        }

        public static Binding IssuerBindingUsername()
        {
            IssuerAddress = IssuerBaseAddress + UsernameMixed;

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
            IssuerAddress = IssuerBaseAddress + WindowsTransport;

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
    }

    /// <summary>
    /// Provides the ability to customize validation X509Certificates.
    /// </summary>
    public class CustomCertificateValidator : X509CertificateValidator
    {
        public override void Validate(X509Certificate2 certificate)
        {
            // perform check here
            return;
        }
    }

    [ServiceContract]
    interface IRequestReply
    {
        [OperationContract(Name ="SendString")]
        string SendString(string message);
    }
}
