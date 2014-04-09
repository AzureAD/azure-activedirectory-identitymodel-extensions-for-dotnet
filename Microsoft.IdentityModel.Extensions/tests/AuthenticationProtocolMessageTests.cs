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
using System.Collections.Generic;
using System.Reflection;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// Tests for AuthenticationProtocolMessage.
    /// </summary>
    [TestClass]
    public class AuthenticationProtocolMessageTests
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
        [TestProperty("TestCaseID", "5e55552c-a805-4367-8708-301adf91780c")]
        [Description("Tests: Constructors")]
        public void AuthenticationProtocolMessage_Constructors()
        {
            AuthenticationProtocolMessage authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage();
        }

        [TestMethod]
        [TestProperty("TestCaseID", "89d0aa7e-f73d-421a-8538-9805d73a23c2")]
        [Description("Tests: Defaults")]
        public void AuthenticationProtocolMessage_Defaults()
        {
            AuthenticationProtocolMessage authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage();
            Assert.AreEqual(authenticationProtocolMessage.IssuerAddress, string.Empty);
            Assert.IsNotNull(authenticationProtocolMessage.Parameters);
            Assert.IsTrue(authenticationProtocolMessage.Parameters.Count == 0);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "407e4efe-3345-4aff-9ce1-4c4d5842fe3f")]
        [Description("Tests: GetSets")]
        public void AuthenticationProtocolMessage_GetSets()
        {
            AuthenticationProtocolMessage authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage();

            List<string> properties = new List<string>()
            {
                "IssuerAddress",
                "PostTitle",
                "ScriptButtonText",
                "ScriptDisabledText",
            };

            foreach(string property in properties)
            { 
                TestUtilities.GetSet(authenticationProtocolMessage, property, null, ExceptionProcessor.ArgumentNullException(substringExpected: property));
                TestUtilities.GetSet(authenticationProtocolMessage, property, property, ExceptionProcessor.NoExceptionExpected);
                TestUtilities.GetSet(authenticationProtocolMessage, property, "    ", ExceptionProcessor.NoExceptionExpected);
                TestUtilities.GetSet(authenticationProtocolMessage, property, "\t\n\r", ExceptionProcessor.NoExceptionExpected);
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "0ae1f9b1-d652-4937-b76a-c771aa4055a2")]
        [Description("Tests: Publics")]
        public void AuthenticationProtocolMessage_Publics()
        {
            string value1 = "value1";
            string value2 = "value2";
            string param1 = "param1";
            string param2 = "param2";

            AuthenticationProtocolMessage authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage();
            ExceptionProcessor expectedException = ExceptionProcessor.ArgumentNullException(substringExpected: "parameter");
            try
            {
                authenticationProtocolMessage.GetParameter(null);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            expectedException = ExceptionProcessor.ArgumentNullException(substringExpected: "parameter");
            try
            {
                authenticationProtocolMessage.RemoveParameter(null);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            expectedException = ExceptionProcessor.ArgumentNullException(substringExpected: "parameter");
            try
            {
                authenticationProtocolMessage.SetParameter(null, null);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            authenticationProtocolMessage.SetParameter(param1, value1);
            authenticationProtocolMessage.RemoveParameter(param2);
            Assert.AreEqual(authenticationProtocolMessage.GetParameter(param1), value1);

            authenticationProtocolMessage.RemoveParameter(param1);
            Assert.IsNull(authenticationProtocolMessage.GetParameter(param1));

            authenticationProtocolMessage.SetParameter(param1, value1);
            authenticationProtocolMessage.SetParameter(param1, value2);
            authenticationProtocolMessage.SetParameter(param2, value2);
            authenticationProtocolMessage.SetParameter(param2, value1);

            Assert.AreEqual(authenticationProtocolMessage.GetParameter(param1), value2);
            Assert.AreEqual(authenticationProtocolMessage.GetParameter(param2), value1);

            authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage(@"http://www.gotjwt.com");
            authenticationProtocolMessage.SetParameter("bob", "     ");

            string queryString = authenticationProtocolMessage.BuildRedirectUrl();
            Assert.IsNotNull(queryString);
            Assert.IsTrue(queryString.Contains("bob"));

            authenticationProtocolMessage.IssuerAddress = string.Empty;
            queryString = authenticationProtocolMessage.BuildRedirectUrl();
            Assert.IsNotNull(queryString);
        }

        /// <summary>
        /// AuthenticationProtocolMessage is abstract use this to test.
        /// </summary>
        private class DerivedAuthenticationProtocolMessage : AuthenticationProtocolMessage
        {
            public DerivedAuthenticationProtocolMessage(string issuerAddress)
                : base(issuerAddress)
            { }

            public DerivedAuthenticationProtocolMessage()
            { }
        }
    }
}