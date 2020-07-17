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
using WcfUtilities;

namespace WsFederationClient
{
    class Program
    {
        static string _saml11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
        static string _saml20 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

        static void Main(string[] args)
        {
            // bypasses certificate validation
            ServicePointManager.ServerCertificateValidationCallback = ValidateServerCertificate;

            IssuerBaseAddress = @"Put base addreess to ADFS here";
            ServiceAddress = "https://127.0.0.1:443/IssuedTokenUsingTls";
            ServiceCert = CertificateUtilities.GetCertificate(StoreName.My, StoreLocation.LocalMachine, X509FindType.FindBySubjectName, "RelyingParty");
            UpnIdentity = "PutUpnIdentity here";
            UsernameMixed = "trust/13/usernamemixed";
            WindowsTransport = "trust/13/windowsTransport";

            bool username = true;
            Binding serviceBinding = null;
            if (username)
                serviceBinding = ServiceBinding(
                    false,
                    SecurityKeyType.SymmetricKey,
                    _saml20,
                    new EndpointAddress(IssuerBaseAddress + UsernameMixed),
                    IssuerBindingUsername(),
                    WSFederationHttpSecurityMode.TransportWithMessageCredential);
            else
                serviceBinding = ServiceBinding(
                    false,
                    SecurityKeyType.SymmetricKey,
                    _saml20,
                     new EndpointAddress(new Uri(IssuerBaseAddress + WindowsTransport), EndpointIdentity.CreateUpnIdentity(UpnIdentity), new AddressHeaderCollection()),
                     IssuerBindingWindowsTransport(),
                     WSFederationHttpSecurityMode.TransportWithMessageCredential);

            var channelFactory = new ChannelFactory<IRequestReply>(serviceBinding, new EndpointAddress(ServiceAddress));

            if (username)
            {
                channelFactory.Credentials.UserName.UserName = "Put username here";
                channelFactory.Credentials.UserName.Password = "Put password here";
            }
            else
            {
                channelFactory.Credentials.Windows.ClientCredential = new NetworkCredential();
            }

            Console.WriteLine($"=========================================");
            Console.WriteLine($"WsFederationClient *** Desktop ***.");
            Console.WriteLine($"ServiceAddess: '{ServiceAddress}'.");
            Console.WriteLine($"IssuerAddress: '{IssuerAddress}'.");
            Console.WriteLine($"=========================================");
            Console.WriteLine($"");

            var requestChannel = channelFactory.CreateChannel();
            try
            {
                var outboundMessage = "Hello";
                Console.WriteLine($"Channel sending:'{outboundMessage}'.");
                Console.WriteLine($"Channel received: '{requestChannel.SendString(outboundMessage)}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Caught Exception => '{ex}'.");
            }

            Console.WriteLine("Press any key to close.");
            Console.ReadKey();
        }

        public static Binding ServiceBinding(bool establishSecurityContext, SecurityKeyType issuedKeyType, string issuedTokenType, EndpointAddress issuerAddress, Binding issuerBinding, WSFederationHttpSecurityMode mode )
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

        public static string IssuerAddress { get; set; }

        public static string IssuerBaseAddress { get; set; }

        public static string UsernameMixed { get; set; }

        public static X509Certificate2 ServiceCert { get; set; }

        public static string ServiceAddress { get; set; }

        public static string WindowsTransport { get; set; }

        public static string UpnIdentity { get; set; }

        static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
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
