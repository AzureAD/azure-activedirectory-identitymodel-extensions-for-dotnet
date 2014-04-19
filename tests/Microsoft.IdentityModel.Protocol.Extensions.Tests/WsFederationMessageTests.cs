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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Reflection;
using System.Web;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class WsFederationMessageTests
    {
        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup(TestContext testContext)
        {
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
        }

        [TestInitialize]
        public void Initialize()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "1bbaf972-ea13-44c4-8f0a-9309e24f8c0e")]
        [Description("Tests: Constructors")]
        public void WsFederationAuthenticationMessage_Constructors()
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

        [TestMethod]
        [TestProperty("TestCaseID", "0217d16e-42b5-4cb5-930e-98e3b4c3c2c6")]
        [Description("Tests: Defaults")]
        public void WsFederationAuthenticationMessage_Defaults()
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

        [TestMethod]
        [TestProperty("TestCaseID", "0c6c4266-8cc5-4fd6-b403-d13f6e1ab38c")]
        [Description("Tests: GetSets")]
        public void WsFederationAuthenticationMessage_GetSets()
        {
            WsFederationMessage wsFederationMessage = new WsFederationMessage();

            Type type = typeof(WsFederationParameterNames);
            FieldInfo[] fields = type.GetFields(BindingFlags.DeclaredOnly | BindingFlags.Public | BindingFlags.Static);
            foreach( FieldInfo fieldInfo in fields)
            {
                TestUtilities.GetSet(wsFederationMessage, fieldInfo.Name, null, new object[]{ fieldInfo.Name, null, fieldInfo.Name + fieldInfo.Name } );
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "6787d22d-5dc3-448c-877d-25fefe5aa062")]
        [Description("Tests: Publics")]
        public void WsFederationAuthenticationMessage_Publics()
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