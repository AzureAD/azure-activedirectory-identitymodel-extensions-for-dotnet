//------------------------------------------------------------------------------
//
// Copyright (c) Brent Schmaltz.
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
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;

namespace WsTrustClient
{
    class Program
    {
        static string _saml11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
        static string _saml20 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
        static string _serviceAddress = "https://127.0.0.1:443/IssuedTokenUsingTls";

        static void Main(string[] args)
        {
            // bypasses certificate validation
            ServicePointManager.ServerCertificateValidationCallback = ValidateServerCertificate;

            try
            {
                string usernameMixed = "trust/13/usernamemixed";
                string windowsMixed = "trust/13/windowsmixed";
                string windowsTransport = "trust/13/windowsTransport";
                string upnIdentity = @"putupnidentityhere";
                string baseAddress = @"putbaseaddresshere";
                string username = @"putusernamehere";
                string password = @"putpasswordhere";

                EndpointReference serviceEndpointReference = new EndpointReference(_serviceAddress);
                WS2007HttpBinding binding = new WS2007HttpBinding();
                EndpointAddress endpointAddress;
                bool usernameCredentials = false;
                bool mixedMode = false;

                Console.WriteLine($"usernameCredentials: '{usernameCredentials}', mixedMode: '{mixedMode}'.");

                if (usernameCredentials)
                {
                    binding.Security.Message.EstablishSecurityContext = false;
                    binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.None;
                    binding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
                    binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                    endpointAddress = new EndpointAddress(baseAddress + usernameMixed);
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
                        endpointAddress = new EndpointAddress(new Uri(baseAddress + windowsMixed), EndpointIdentity.CreateUpnIdentity(upnIdentity), new AddressHeaderCollection());
                    }
                    else
                    {
                        binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Windows;
                        binding.Security.Message.ClientCredentialType = MessageCredentialType.Windows;
                        binding.Security.Mode = SecurityMode.Transport;
                        endpointAddress = new EndpointAddress(new Uri(baseAddress + windowsTransport), EndpointIdentity.CreateUpnIdentity(upnIdentity), new AddressHeaderCollection());
                    }
                }

                WSTrustChannelFactory trustChannelFactory = new WSTrustChannelFactory(binding, endpointAddress)
                {
                    TrustVersion = TrustVersion.WSTrust13
                };

                SecurityToken token = null;
                if (usernameCredentials)
                {
                    trustChannelFactory.Credentials.UserName.UserName = username;
                    trustChannelFactory.Credentials.UserName.Password = password;
                }
                else
                {
                    trustChannelFactory.Credentials.Windows.ClientCredential = new NetworkCredential();
                }

                WSTrustChannel tokenClient = (WSTrustChannel)trustChannelFactory.CreateChannel();
                RequestSecurityToken rst = new RequestSecurityToken(RequestTypes.Issue)
                {
                    KeyType = KeyTypes.Symmetric,
                    AppliesTo = serviceEndpointReference,
                    TokenType = _saml11
                };

                token = tokenClient.Issue(rst);
                Console.WriteLine($"SecurityToken: '{token}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception from TrustChannel: '{ex}'.");
            }

            Console.WriteLine($"Press a key to close.");
            Console.ReadKey();
        }

        static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine($"ValidateServerCertificate.\nsslPolicyErrors:'{sslPolicyErrors}'\ncertificate:'{certificate}'.");

            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            return true;
        }
    }
}
