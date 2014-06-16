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
    public class OpenIdConnectProtocolValidationParametersTests
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
        [TestProperty("TestCaseID", "4696852e-94e7-4c2b-a768-ce6e7f16e80d")]
        [Description("Tests: GetSets, test covers defaults")]
        public void OpenIdConnectProtocolValidationParameters_GetSets()
        {
            OpenIdConnectProtocolValidationParameters validationParameters = new OpenIdConnectProtocolValidationParameters();
            Type type = typeof(OpenIdConnectProtocolValidationParameters);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 7)
                Assert.Fail("Number of properties has changed from 7 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>> 
                    { 
                        new KeyValuePair<string, List<object>>("RequireAcr", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireAmr", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireAuthTime", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireAzp", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireNonce", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("ResponseType", new List<object>{OpenIdConnectMessage.DefaultResponseType, OpenIdConnectResponseTypes.IdToken, OpenIdConnectResponseTypes.CodeIdToken}),
                    },
                    Object = validationParameters,
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
            
            ExpectedException ee = ExpectedException.ArgumentNullException();
            try
            {
                validationParameters.ResponseType = null;
                ee.ProcessNoException();
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }

            Assert.IsNotNull(validationParameters.AlgorithmMap);
            Assert.AreEqual(validationParameters.AlgorithmMap.Count, 9);

            try
            {
                validationParameters.AlgorithmMap = null;
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }

            validationParameters.AlgorithmMap = JwtSecurityTokenHandler.InboundAlgorithmMap;
            Assert.IsTrue(IdentityComparer.AreEqual(JwtSecurityTokenHandler.InboundAlgorithmMap, validationParameters.AlgorithmMap));
        }
    }
}