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
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

#pragma warning disable CS3003 // Binding, EndpointAddress not CLS-compliant

namespace Microsoft.IdentityModel.Wcf
{
    /// <summary>
    /// 
    /// </summary>
    public class WsTrustClient
    {
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="binding"></param>
        /// <param name="endPointAddress"></param>
        public WsTrustClient(Binding binding, EndpointAddress endPointAddress)
        {
            Binding = binding;
            EndpointAddress = endPointAddress;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="wsTrustRequest"></param>
        /// <returns></returns>
        public WsTrustResponse WsTrustResponse(WsTrustRequest wsTrustRequest)
        {
            ServicePointManager.ServerCertificateValidationCallback = RemoteCertificateValidationCallback;
            try
            {
                var factory = new ChannelFactory<IRequestChannel>(Binding, EndpointAddress);
                factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
                var channel = factory.CreateChannel();
                var memeoryStream = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(memeoryStream, Encoding.UTF8);
                var serializer = new WsTrustSerializer();
                serializer.WriteRequest(writer, WsTrustVersion.Trust13, wsTrustRequest);
                writer.Flush();
                var bytes = memeoryStream.ToArray();
                var reader = XmlDictionaryReader.CreateTextReader(bytes, XmlDictionaryReaderQuotas.Max);
                var requestMessage = Message.CreateMessage(MessageVersion.Soap12WSAddressing10, "https://127.0.0.1/wsTrust13/transportIWA", reader);
                var responseMessage = channel.Request(requestMessage);
                var response = responseMessage.GetReaderAtBodyContents();
                return serializer.ReadResponse(response);
            }
            catch(Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="certificate"></param>
        /// <param name="chain"></param>
        /// <param name="sslPolicyErrors"></param>
        /// <returns></returns>
        public static bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        public Binding Binding { get; }

        /// <summary>
        /// 
        /// </summary>
        public EndpointAddress EndpointAddress { get; }
    }
}
