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
using System.Collections.Generic;
using System.IdentityModel.Test;
using Xunit;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// Tests for AuthenticationProtocolMessage.
    /// </summary>
    public class AuthenticationProtocolMessageTests
    {
        [Fact(DisplayName = "AuthenticationProtocolMessageTests: Defaults")]
        public void Defaults()
        {
            List<string> errors = new List<string>();
            string issuerAddress = "http://www.gotjwt.com";

            AuthenticationProtocolMessage authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage();
            if (!IdentityComparer.AreStringsEqual(authenticationProtocolMessage.IssuerAddress, string.Empty, CompareContext.Default))
            {
                errors.Add("authenticationProtocolMessage.IssuerAddress != string.Empty: " + authenticationProtocolMessage.IssuerAddress ?? "null");
            }

            authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage(issuerAddress);
            if (!IdentityComparer.AreStringsEqual(authenticationProtocolMessage.IssuerAddress, issuerAddress, CompareContext.Default))
            {
                errors.Add("authenticationProtocolMessage.IssuerAddress != issuerAddress: " + authenticationProtocolMessage.IssuerAddress ?? "null" + " , " + issuerAddress);
            }

            if (authenticationProtocolMessage.Parameters == null)
            {
                errors.Add("uthenticationProtocolMessage.Parameters .IssuerAddress != issuerAddress: " + authenticationProtocolMessage.IssuerAddress ?? "null" + " , " + issuerAddress);
            }

            Assert.NotNull(authenticationProtocolMessage.Parameters);
            Assert.Equal(authenticationProtocolMessage.Parameters.Count, 0);
        }

        [Fact(DisplayName = "AuthenticationProtocolMessageTests: GetSets")]
        public void GetSets()
        {
            AuthenticationProtocolMessage authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage("http://www.gotjwt.com");

            List<string> properties = new List<string>()
            {
                "IssuerAddress",
                "PostTitle",
                "ScriptButtonText",
                "ScriptDisabledText",
            };

            foreach(string property in properties)
            {
                TestUtilities.SetGet(authenticationProtocolMessage, property, null, ExpectedException.ArgumentNullException(substringExpected: property));
                TestUtilities.SetGet(authenticationProtocolMessage, property, property, ExpectedException.NoExceptionExpected);
                TestUtilities.SetGet(authenticationProtocolMessage, property, "    ", ExpectedException.NoExceptionExpected);
                TestUtilities.SetGet(authenticationProtocolMessage, property, "\t\n\r", ExpectedException.NoExceptionExpected);
            }
        }

        [Fact(DisplayName = "AuthenticationProtocolMessageTests: Publics")]
        public void Publics()
        {
            string value1 = "value1";
            string value2 = "value2";
            string param1 = "param1";
            string param2 = "param2";

            AuthenticationProtocolMessage authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage("http://www.gotjwt.com");
            ExpectedException expectedException = ExpectedException.ArgumentNullException(substringExpected: "parameter");
            try
            {
                authenticationProtocolMessage.GetParameter(null);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            expectedException = ExpectedException.ArgumentNullException(substringExpected: "parameter");
            try
            {
                authenticationProtocolMessage.RemoveParameter(null);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            expectedException = ExpectedException.ArgumentNullException(substringExpected: "parameter");
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
            Assert.Equal(authenticationProtocolMessage.GetParameter(param1), value1);

            authenticationProtocolMessage.RemoveParameter(param1);
            Assert.Null(authenticationProtocolMessage.GetParameter(param1));

            authenticationProtocolMessage.SetParameter(param1, value1);
            authenticationProtocolMessage.SetParameter(param1, value2);
            authenticationProtocolMessage.SetParameter(param2, value2);
            authenticationProtocolMessage.SetParameter(param2, value1);

            Assert.Equal(authenticationProtocolMessage.GetParameter(param1), value2);
            Assert.Equal(authenticationProtocolMessage.GetParameter(param2), value1);

            authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage(@"http://www.gotjwt.com");
            authenticationProtocolMessage.SetParameter("bob", "     ");

            string queryString = authenticationProtocolMessage.BuildRedirectUrl();
            Assert.NotNull(queryString);
            Assert.True(queryString.Contains("bob"));

            authenticationProtocolMessage.IssuerAddress = string.Empty;
            queryString = authenticationProtocolMessage.BuildRedirectUrl();
            Assert.NotNull(queryString);
        }

        /// <summary>
        /// AuthenticationProtocolMessage is abstract use this to test.
        /// </summary>
        private class DerivedAuthenticationProtocolMessage : AuthenticationProtocolMessage
        {
            public DerivedAuthenticationProtocolMessage()
            { }

            public DerivedAuthenticationProtocolMessage(string issuerAddress)
                : base(issuerAddress)
            { }
        }
    }
}