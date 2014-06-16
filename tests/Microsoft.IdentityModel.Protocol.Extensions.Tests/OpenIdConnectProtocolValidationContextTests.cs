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
using System.IdentityModel.Test;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Text;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class OpenIdConnectProtocolValidationContextTests
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
        [TestProperty("TestCaseID", "E040FDE8-26C8-4F4A-A005-A8A44185FC24")]
        [Description("Tests: GetSets, test covers defaults")]
        public void OpenIdConnectProtocolValidationContext_GetSets()
        {
            OpenIdConnectProtocolValidationContext validationContext = new OpenIdConnectProtocolValidationContext();
            Type type = typeof(OpenIdConnectProtocolValidationContext);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 3)
                Assert.Fail("Number of properties has changed from 3 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>> 
                    { 
                        new KeyValuePair<string, List<object>>("AuthorizationCode", new List<object>{(string)null, "AuthorizationCode", "AuthorizationCode_AuthorizationCode"}),
                        new KeyValuePair<string, List<object>>("Nonce", new List<object>{(string)null, "Nonce", "Nonce_Nonce"}),                            
                    },
                    Object = validationContext,
                };
            TestUtilities.GetSet(context);

            if (context.Errors.Count != 0)
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine(Environment.NewLine);
                foreach(string str in context.Errors)
                    sb.AppendLine(str);

                Assert.Fail(sb.ToString());
            }

            Assert.IsNotNull(validationContext.OpenIdConnectProtocolValidationParameters);
            TestUtilities.SetGet(validationContext, "OpenIdConnectProtocolValidationParameters", (OpenIdConnectProtocolValidationParameters)null, ExpectedException.ArgumentNullException());
            TestUtilities.SetGet(validationContext, "OpenIdConnectProtocolValidationParameters", new OpenIdConnectProtocolValidationParameters(), ExpectedException.NoExceptionExpected);
        }
    }
}