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
using System.Reflection;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.WsFederation.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class WsFederationMessageTests
    {
        [Fact]
        public void Constructors()
        {
            WsFederationMessage wsFederationMessage = new WsFederationMessage();
            Assert.AreEqual(wsFederationMessage.IssuerAddress, string.Empty);

            wsFederationMessage = new WsFederationMessage("http://www.got.jwt.com");
            Assert.AreEqual(wsFederationMessage.IssuerAddress, "http://www.got.jwt.com");

            ExpectedException expectedException = ExpectedException.ArgumentNullException("issuerAddress");
            try
            {
                wsFederationMessage = new WsFederationMessage((string)null);
                expectedException.ProcessNoException();
            }
            catch(Exception exception)
            {
                expectedException.ProcessException(exception);
            }
        }

        [Fact]
        public void Defaults()
        {
            WsFederationMessage wsFederationMessage = new WsFederationMessage();

            Assert.AreEqual(wsFederationMessage.IssuerAddress, string.Empty);
            Assert.IsNull(wsFederationMessage.Wa);
            Assert.IsNull(wsFederationMessage.Wauth);
            Assert.IsNull(wsFederationMessage.Wct);
            Assert.IsNull(wsFederationMessage.Wctx);
            Assert.IsNull(wsFederationMessage.Wencoding);
            Assert.IsNull(wsFederationMessage.Wfed);
            Assert.IsNull(wsFederationMessage.Wfresh);
            Assert.IsNull(wsFederationMessage.Whr);
            Assert.IsNull(wsFederationMessage.Wp);
            Assert.IsNull(wsFederationMessage.Wpseudo);
            Assert.IsNull(wsFederationMessage.Wpseudoptr);
            Assert.IsNull(wsFederationMessage.Wreply);
            Assert.IsNull(wsFederationMessage.Wreq);
            Assert.IsNull(wsFederationMessage.Wreqptr);
            Assert.IsNull(wsFederationMessage.Wres);
            Assert.IsNull(wsFederationMessage.Wresult);
            Assert.IsNull(wsFederationMessage.Wresultptr);
            Assert.IsNull(wsFederationMessage.Wtrealm);
        }

        [Fact]
        public void GetSets()
        {
            WsFederationMessage wsFederationMessage = new WsFederationMessage();

            Type type = typeof(WsFederationParameterNames);
            FieldInfo[] fields = type.GetFields(BindingFlags.DeclaredOnly | BindingFlags.Public | BindingFlags.Static);
            foreach( FieldInfo fieldInfo in fields)
            {
                TestUtilities.GetSet(wsFederationMessage, fieldInfo.Name, null, new object[]{ fieldInfo.Name, null, fieldInfo.Name + fieldInfo.Name } );
            }
        }

        [Fact]
        public void Publics()
        {
            string issuerAdderss = @"http://www.gotjwt.com";
            string wreply = @"http://www.relyingparty.com";
            string wct = Guid.NewGuid().ToString();
            WsFederationMessage wsFederationMessage = new WsFederationMessage
            {
                IssuerAddress = issuerAdderss,
                Wreply = wreply,
                Wct = wct,
            };

            wsFederationMessage.SetParameter("bob", null);
            wsFederationMessage.Parameters.Add("bob", null);
            string uriString = wsFederationMessage.BuildRedirectUrl();
            Uri uri = new Uri(uriString);

            WsFederationMessage wsFederationMessageReturned = WsFederationMessage.FromQueryString(uri.Query);
            wsFederationMessageReturned.IssuerAddress = issuerAdderss;
            wsFederationMessageReturned.Parameters.Add("bob", null);
            Assert.IsTrue(MessageComparer.AreEqual(wsFederationMessage, wsFederationMessageReturned));

            wsFederationMessageReturned = WsFederationMessage.FromUri(uri);
            wsFederationMessageReturned.IssuerAddress = issuerAdderss;
            wsFederationMessageReturned.Parameters.Add("bob", null);
            Assert.IsTrue(MessageComparer.AreEqual(wsFederationMessage, wsFederationMessageReturned));
        }
    }
}
