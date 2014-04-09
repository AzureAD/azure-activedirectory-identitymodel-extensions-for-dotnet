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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IdentityModel.Tokens;

namespace System.IdentityModel.Test
{
    [TestClass]
    public class NamedKeyTest 
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;

        [ClassInitialize]
        public static void ClassSetup( TestContext testContext )
        {
        }

        [TestInitialize]
        public void Initialize()
        {
            _testContextProvider = new TestContextProvider( TestContext );
        }

        /// <summary>
        /// The test context that is set by Visual Studio and TAEF - need to keep this exact signature
        /// </summary>
        public TestContext TestContext { get; set; }

        private class NameKeyParametersVariation
        {
            public string TestCase { get; set; }
            public Action TestAction { get; set; }
        }

        private static NameKeyParametersVariation[] CreateTestVariations()
        {
            NameKeyParametersVariation[] variations =
                {
                    new NameKeyParametersVariation
                        {
                            TestCase = "MatchesName",
                            TestAction =
                                () => (new NamedKeySecurityKeyIdentifierClause("bob", null)).Matches(null)
                        },
                    new NameKeyParametersVariation
                        {
                            TestCase = "LoadCustomConfiguration",
                            TestAction =
                                () =>
                                ( new NamedKeyIssuerTokenResolver( new Dictionary<string, IList<SecurityKey>>() ) ).LoadCustomConfiguration( null )
                        },
                    new NameKeyParametersVariation
                        {
                            TestCase = "NamedKeySecurityTokenString",
                            TestAction =
                                () =>
                                new NamedKeySecurityToken( null,  null )
                        },
                    new NameKeyParametersVariation
                        {
                            TestCase = "NamedKeySecurityTokenKeys",
                            TestAction =
                                () =>
                                new NamedKeySecurityToken( "bob", null )
                        },
                    new NameKeyParametersVariation
                        {
                            TestCase = "ResolveKeyIdentifierClause",
                            TestAction =
                                () =>
                                ( new NamedKeySecurityToken( "bob", new List<SecurityKey>() ) ).MatchesKeyIdentifierClause( null )
                        },
                };

            return variations;
        }

        private static void RunVariations(NameKeyParametersVariation[] variations)
        {
            foreach (NameKeyParametersVariation variation in variations)
            {
                try
                {
                    variation.TestAction();
                    Assert.Fail("Testcase: '{0}'. Expecting: To throw exception '{1}'", variation.TestCase, typeof(ArgumentNullException).ToString());
                }
                catch (ArgumentNullException)
                {
                    // This is the expected case.
                }
                catch (Exception ex)
                {
                    Assert.Fail(
                        "Testcase: '{0}'. Expecting: To catch exception '{1}', caught: '{2}'",
                        variation.TestCase,
                        typeof(ArgumentNullException),
                        ex.GetType());
                }
            }            
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "98F34DF6-921C-4F46-BB02-EA2B5F6C372C" )]
        [Description( "NamedKeyParameter Tests" )]
        public void NamedKeyParameter()
        {
            NameKeyParametersVariation[] variations = CreateTestVariations();
            RunVariations( variations );
        }
    }
}
