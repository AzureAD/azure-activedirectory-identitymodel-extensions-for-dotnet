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
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Federation;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Threading;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens.Saml2;

#pragma warning disable CS3003 // Binding, EndpointAddress not CLS-compliant
namespace WsFederationClient
{
    /// <summary>
    /// This program is a .NET core 3.1 application that will obtain a Saml2Token from a local STS
    /// attach the token to an outbound HttpBinding using TransportWithMessageSecurity and IssuedToken.
    /// There is code in this 
    /// </summary>
    class Program
    {
        static string _wsFedMetadata = "<put metadata address here>";
        static string _saml11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
        static string _saml20 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

        static void Main(string[] args)
        {
            ServicePointManager.ServerCertificateValidationCallback = ValidateServerCertificate;

            BaseAddress = @"<put base address here>";
            ServiceAddress = "https://127.0.0.1:443/IssuedTokenUsingTls";
            //ServiceCert = CertificateUtilities.GetCertificate(StoreName.My, StoreLocation.LocalMachine, X509FindType.FindBySubjectName, "RelyingParty");
            UpnIdentity = "<put upnidentity here, this is the UPN of the user account that ADFS is running as>";
            UsernameMixed = "trust/13/usernamemixed";
            WindowsMixed = "trust/13/windowsmixed";
            WindowsTransport = "trust/13/windowsTransport";

            System.ServiceModel.Security.Tokens.IssuedSecurityTokenParameters istp = new System.ServiceModel.Security.Tokens.IssuedSecurityTokenParameters();
            var federationBinding = new WsFederationHttpBinding(
                new IssuedSecurityTokenParameters
                {
                    IssuerAddress = new EndpointAddress(new Uri(BaseAddress + UsernameMixed)),
                    IssuerBinding = StsBinding(false, false),
                    //SecurityKey = new SymmetricSecurityKey(Guid.NewGuid().ToByteArray()),
                    //Target = ServiceAddress,
                    TokenType = Saml2Constants.OasisWssSaml2TokenProfile11
                });

            var channelFactory = new ChannelFactory<IRequestReply>(federationBinding, new EndpointAddress(new Uri(ServiceAddress)));
            channelFactory.Endpoint.EndpointBehaviors.Remove(typeof(ClientCredentials));
            channelFactory.Endpoint.EndpointBehaviors.Add(new WsTrustChannelClientCredentials());
            channelFactory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
            channelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication
            {
                CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None
            };

            channelFactory.Credentials.UserName.UserName = "<put username here>";
            channelFactory.Credentials.UserName.Password = "<put passord here>";
            channelFactory.Credentials.Windows.ClientCredential = new NetworkCredential();

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

        public static string BaseAddress { get; set; }

        public static string UsernameMixed { get; set; }

        public static X509Certificate2 ServiceCert { get; set; }

        public static string ServiceAddress { get; set; }

        public static string WindowsMixed { get; set; }

        public static string WindowsTransport { get; set; }

        public static string UpnIdentity { get; set; }

        public static Binding StsBinding(bool usernameCredentials, bool mixedMode)
        {
            WS2007HttpBinding binding = new WS2007HttpBinding();
            if (usernameCredentials)
            {
                binding.Security.Message.EstablishSecurityContext = false;
                binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.None;
                binding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
                binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                EndpointAddress = new EndpointAddress(BaseAddress + UsernameMixed);
            }
            else
            {
                binding.Security.Message.EstablishSecurityContext = false;
                if (mixedMode)
                {
                    binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.None;
                    binding.Security.Message.ClientCredentialType = MessageCredentialType.Windows;
                    binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                    binding.Security.Message.NegotiateServiceCredential = false;
                    EndpointAddress = new EndpointAddress(new Uri(BaseAddress + WindowsMixed), EndpointIdentity.CreateUpnIdentity(UpnIdentity), new AddressHeader[0]);
                }
                else
                {
                    binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Windows;
                    binding.Security.Mode = SecurityMode.Transport;
                    EndpointAddress = new EndpointAddress(new Uri(BaseAddress + WindowsTransport), EndpointIdentity.CreateUpnIdentity(UpnIdentity), new AddressHeader[0]);
                }
            }

            return binding;
        }

        public static void GetFedMetadata()
        {
            WsFederationConfigurationRetriever wsFederationConfigurationRetriever = new WsFederationConfigurationRetriever();
            ConfigurationManager<WsFederationConfiguration> configurationManager = new ConfigurationManager<WsFederationConfiguration>(_wsFedMetadata, wsFederationConfigurationRetriever);
            try
            {
                var configuration = WsFederationConfigurationRetriever.GetAsync(_wsFedMetadata, CancellationToken.None).GetAwaiter().GetResult();
                var config = configurationManager.GetConfigurationAsync().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Caught exception getting WsFedMetadata from: '{_wsFedMetadata}'. Exception: '{ex}'.");
            }

        }

        static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            return true;
        }
    }

    [ServiceContract]
    interface IRequestReply
    {
        [OperationContract(Name ="SendString")]
        string SendString(string message);
    }
}
