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
using Microsoft.IdentityModel.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.Tests
{
    /// <summary>
    /// Tests for AuthenticationProtocolMessage.
    /// </summary>
    public class AuthenticationProtocolMessageTests
    {
        [Fact]
        public void Defaults()
        {
            List<string> errors = new List<string>();
            string issuerAddress = "http://www.gotjwt.com";

            AuthenticationProtocolMessage authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage();
            if (!IdentityComparer.AreStringsEqual(authenticationProtocolMessage.IssuerAddress, string.Empty, CompareContext.Default))
            {
                errors.Add("authenticationProtocolMessage.IssuerAddress != string.Empty: " + authenticationProtocolMessage.IssuerAddress ?? "null");
            }

            authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage() { IssuerAddress = issuerAddress };
            if (!IdentityComparer.AreStringsEqual(authenticationProtocolMessage.IssuerAddress, issuerAddress, CompareContext.Default))
            {
                errors.Add("authenticationProtocolMessage.IssuerAddress != issuerAddress: " + authenticationProtocolMessage.IssuerAddress ?? "null" + " , " + issuerAddress);
            }

            if (authenticationProtocolMessage.Parameters == null)
            {
                errors.Add("uthenticationProtocolMessage.Parameters .IssuerAddress != issuerAddress: " + authenticationProtocolMessage.IssuerAddress ?? "null" + " , " + issuerAddress);
            }

            Assert.NotNull(authenticationProtocolMessage.Parameters);
            Assert.Equal(0, authenticationProtocolMessage.Parameters.Count);
        }

        [Fact]
        public void GetSets()
        {
            var authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage() { IssuerAddress = "http://www.gotjwt.com" };

            var properties = new List<string>()
            {
                "IssuerAddress",
                "PostTitle",
                "ScriptButtonText",
                "ScriptDisabledText",
            };

            var context = new GetSetContext();
            foreach(string property in properties)
            {
                TestUtilities.SetGet(authenticationProtocolMessage, property, null, ExpectedException.ArgumentNullException(substringExpected: "value"), context);
                TestUtilities.SetGet(authenticationProtocolMessage, property, property, ExpectedException.NoExceptionExpected, context);
                TestUtilities.SetGet(authenticationProtocolMessage, property, "    ", ExpectedException.NoExceptionExpected, context);
                TestUtilities.SetGet(authenticationProtocolMessage, property, "\t\n\r", ExpectedException.NoExceptionExpected, context);
            }

            TestUtilities.AssertFailIfErrors(context.Errors);
        }

        [Fact]
        public void Publics()
        {
            string value1 = "value1";
            string value2 = "value2";
            string param1 = "param1";
            string param2 = "param2";

            AuthenticationProtocolMessage authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage() { IssuerAddress = "http://www.gotjwt.com" };
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

            authenticationProtocolMessage = new DerivedAuthenticationProtocolMessage() { IssuerAddress = "http://www.gotjwt.com" };
            authenticationProtocolMessage.SetParameter("bob", "     ");

            string queryString = authenticationProtocolMessage.BuildRedirectUrl();
            Assert.NotNull(queryString);
            Assert.Contains("bob", queryString);

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
        }
    }
}
