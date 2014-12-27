//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using Microsoft.IdentityModel.Protocols;
using System;
using System.IdentityModel.Test;
using System.Reflection;
using Xunit;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    public class WsFederationMessageTests
    {
        [Fact(DisplayName = "WsFederationMessageTests: Constructors")]
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

        [Fact(DisplayName = "WsFederationMessageTests: Defaults")]
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

        [Fact(DisplayName = "WsFederationMessageTests: GetSets")]
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

        [Fact(DisplayName = "WsFederationMessageTests: Publics")]
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