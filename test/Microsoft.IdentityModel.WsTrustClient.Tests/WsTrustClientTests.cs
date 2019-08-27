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
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Wcf;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.WsTrustClient.Tests
{
    public class WsTrustClientTests
    {
        [Fact]
        public void CallSTS()
        {
            ServicePointManager.ServerCertificateValidationCallback = RemoteCertificateValidationCallback;


            var binding = new WSHttpBinding(SecurityMode.Transport);
            binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Windows;
            var epi = new DnsEndpointIdentity("https://127.0.0.1:5443/");
            //var epa = new EndpointAddress(new Uri(baseAddress), epi, new AddressHeaderCollection());

            var endpoint = new EndpointAddress(new Uri("https://127.0.0.1:5443/wsTrust13/transportIWA"), epi, new AddressHeader[0]);

            var wstrustClient = new Microsoft.IdentityModel.Wcf.WsTrustClient(binding, endpoint);
            var wsTrustRequest = new WsTrustRequest();
            var wsTrustResponse = wstrustClient.WsTrustResponse(wsTrustRequest);
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

    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
