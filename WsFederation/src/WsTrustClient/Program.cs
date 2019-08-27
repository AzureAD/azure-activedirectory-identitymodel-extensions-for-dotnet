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
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsTrust;

#pragma warning disable CS3003 // Binding, EndpointAddress not CLS-compliant
namespace WsTrustClient
{
    /// <summary>
    /// This program is a .NET core 3.1 application that will obtain a Saml2Token from a local STS
    /// attach the token to an outbound HttpBinding using TransportWithMessageSecurity and IssuedToken.
    /// </summary>
    class Program
    {
        static string _authority = "https://127.0.0.1:5443/WsTrust13/transportIWA";
        static string _saml20 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
        static string _serviceAddress = "https://127.0.0.1:443/IssuedTokenUsingTls";

        static void Main(string[] args)
        {
            ServicePointManager.ServerCertificateValidationCallback = RemoteCertificateValidationCallback;

            var federationBinding = new WsFederationBinding(new IssuedTokenParameters
            {
                IssuerAddress = new EndpointAddress(new Uri(_authority)),
                IssuerBinding = new WSHttpBinding(SecurityMode.Transport),
                IssuedKeyType = "bearerKey",
                IssuedTokenType = _saml20,
                WsTrustVersion = WsTrustVersion.Trust13,
            });

            // Create the channel factory for the IRequestReply message exchange pattern.
            var factory = new ChannelFactory<IRequestReply>(federationBinding, new EndpointAddress(new Uri(_serviceAddress)));

            factory.Endpoint.EndpointBehaviors.Remove(typeof(ClientCredentials));
            factory.Endpoint.EndpointBehaviors.Add(new WSTrustChannelClientCredentials());
            factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            factory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication
            {
                CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None
            };

            // Create the channel.
            var channel = factory.CreateChannel();

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

        public static bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }

    // using RequestChannel
    // using RequestChannel, requires Open, close and specific Action
    // var factory = new ChannelFactory<IRequestChannel>(federationBinding, new EndpointAddress(new Uri(_serviceAddress)));
    //channel.Open();
    //var replyMessage = channel.Request(Message.CreateMessage(MessageVersion.Soap12WSAddressing10, "http://tempuri.org/IRequestReply/SendString", new CustomBodyWriter()));

    [ServiceContract]
    interface IRequestReply
    {
        [OperationContract(Name ="SendString")]
        string SendString(string message);
    }

    public class CustomBodyWriter : BodyWriter
    {
        private string _bodyContent;

        public CustomBodyWriter() : base(true)
        { }

        public CustomBodyWriter(string message) : base(true)
        {
            _bodyContent = message;
        }

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement("SendString", "http://tempuri.org/");
            writer.WriteElementString("message", "Hello");
            writer.WriteEndElement();
        }
    }
}
