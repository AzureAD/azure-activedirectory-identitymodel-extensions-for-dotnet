//------------------------------------------------------------------------------
//     Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Xml;

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
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "NamedKeyParameter Tests" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void NamedKeyParameter()
        {
            NameKeyParametersVariation[] variations = CreateTestVariations();
            RunVariations( variations );
        }
    }
}
