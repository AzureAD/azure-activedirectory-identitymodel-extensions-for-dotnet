//------------------------------------------------------------------------------
//     Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace System.IdentityModel.Test
{

    [TestClass]
    public class NamedKeyIssuerTokenResolverDefaultConfigTest : ConfigurationTest
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

        public NamedKeyIssuerTokenResolverDefaultConfigTest()
        {
        }

        protected override string GetConfiguration( string testVariation )
        {
            return @"<system.identityModel>
                       <identityConfiguration> 
                         <issuerTokenResolver type='" + typeof( NamedKeyIssuerTokenResolver ).AssemblyQualifiedName + @"' />
                       </identityConfiguration> 
                     </system.identityModel>";
        }

        protected override void ValidateTestCase( string testVariation )
        {
            IdentityConfiguration identityConfig = new IdentityConfiguration( IdentityConfiguration.DefaultServiceName );

            Assert.IsNotNull( identityConfig.IssuerTokenResolver );

            Assert.IsFalse( identityConfig.IssuerTokenResolver.GetType() != typeof( NamedKeyIssuerTokenResolver ) , string.Format( "Expected identityConfiguration.IsuerTokenResolver.GetType() == typeof( NamedKeyIssuerTokenResolver ), was: '{0}'", identityConfig.IssuerTokenResolver.GetType() ) );

            NamedKeyIssuerTokenResolver resolver = identityConfig.IssuerTokenResolver as NamedKeyIssuerTokenResolver;

            Assert.IsTrue( resolver.SecurityKeys.Count == 0 );
            Assert.IsTrue( IssuerTokenResolver.DefaultStoreName == StoreName.TrustedPeople );
            Assert.IsTrue( IssuerTokenResolver.DefaultStoreLocation == StoreLocation.LocalMachine );

            // Should not find key
            SecurityKey key = null;
            NamedKeySecurityKeyIdentifierClause clause = new NamedKeySecurityKeyIdentifierClause( "keyName", "KeyingMaterial.SymmetricKeyBytes_256" );

            Assert.IsFalse( resolver.TryResolveSecurityKey( clause, out key ) );
            Assert.IsNull( key );

            // Should not find token
            SecurityToken token = null;
            Assert.IsFalse( resolver.TryResolveToken( clause, out token ) );
            Assert.IsNull( token );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "5BD621E8-9427-499D-A9D3-941BD2672752" )]
        [TestProperty( "TestType", "BVT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Default NamedKeyIssuerTokenResolver" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void LoadNamedKeyIssuerTokenResolver()
        {
            RunTestCase( string.Empty );
        }
    }

    [TestClass]
    public class NamedKeyIssuerTokenResolverMultipleKeysConfigTest : ConfigurationTest
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;

        [ClassInitialize]
        public static void ClassSetup( TestContext testContext )
        {
        }

        public NamedKeyIssuerTokenResolverMultipleKeysConfigTest()
        { }

        protected override string GetConfiguration( string testVariation )
        {
            return @"
                    <system.identityModel>
                        <identityConfiguration> 
                            <issuerTokenResolver type='System.IdentityModel.Tokens.NamedKeyIssuerTokenResolver, System.IdentityModel.Tokens.JWT'>
                                <securityKey symmetricKey='jWo8qtxA05mPwwjMPhIS7w==' name='LocalSTS' />
                                <securityKey symmetricKey='Vbxq2mlbGJw8XH+ZoYBnUHmHga8/o/IduvU/Tht70iE=' name='LiveId' />
                                <securityKey symmetricKey='Vbxq2mlbGJw8XH+ZoYBnUHmHga8/o/IduvU/Tht70iE=' name='LocalSTS' />
                            </issuerTokenResolver>
                        </identityConfiguration> 
                    </system.identityModel>";
        }

        protected override void ValidateTestCase( string testCase )
        {
            IdentityConfiguration identityConfig = new IdentityConfiguration( IdentityConfiguration.DefaultServiceName );

            Assert.IsNotNull( identityConfig.IssuerTokenResolver );

            Assert.IsFalse( identityConfig.IssuerTokenResolver.GetType() != typeof( NamedKeyIssuerTokenResolver ) , string.Format( "Expected identityConfiguration.IsuerTokenResolver.GetType() == typeof( NamedKeyIssuerTokenResolver ), was: '{0}'", identityConfig.IssuerTokenResolver.GetType() ) );

            NamedKeyIssuerTokenResolver resolver = identityConfig.IssuerTokenResolver as NamedKeyIssuerTokenResolver;

            Assert.IsTrue( resolver.SecurityKeys.Count == 2 );
            Assert.IsTrue( IssuerTokenResolver.DefaultStoreName == StoreName.TrustedPeople );
            Assert.IsTrue( IssuerTokenResolver.DefaultStoreLocation == StoreLocation.LocalMachine );

            // Should find key
            SecurityKey key = KeyingMaterial.SymmetricSecurityKey_256;
            NamedKeySecurityKeyIdentifierClause clause = new NamedKeySecurityKeyIdentifierClause( "LiveId", "key" );

            Assert.IsTrue( resolver.TryResolveSecurityKey( clause, out key ) );
            Assert.IsNotNull( key );

            // Should not find token
            SecurityToken token = null;
            Assert.IsTrue( resolver.TryResolveToken( clause, out token ) );
            Assert.IsNotNull( token );

            //Verify.IsNotNull( resolver.XmlNodes );

            List<string> nodeNames = new List<string>() { "securityKeyProvider", "List" };
            //int index = 0;

            //foreach ( XmlNode node in resolver.XmlNodes )
            //{
            //    Assert.IsTrue( string.Equals( node.Name, nodeNames[index++], StringComparison.Ordinal ) );
            //}
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "1E62250E-9208-4917-8677-0C82EFE6823E" )]
        [TestProperty( "TestType", "BVT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "MultiKey NamedKeyIssuerTokenResolver" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void MultiKeyNamedKeyIssuerTokenResolver()
        {
            RunTestCase( string.Empty );
        }
    }

    [TestClass]
    public class NamedKeyIssuerTokenResolverInvalidConfig : ConfigurationTest
    {
        static Dictionary<string, string> _testCases = new Dictionary<string, string>();

        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;

        public NamedKeyIssuerTokenResolverInvalidConfig()
        {
        }

        [ClassInitialize]
        public static void ClassSetup( TestContext testContext )
        {
            _testCases.Add( "AsymmetricKey",
                    @"<issuerTokenResolver type='System.IdentityModel.Tokens.NamedKeyIssuerTokenResolver, System.IdentityModel.Tokens.JWT'>
                        <securityKey asymmetricKey='jWo8qtxA05mPwwjMPhIS7w==' name='LocalSTS' />
                    </issuerTokenResolver>" );

            _testCases.Add( "MissingSymmetricKey",
                    @"<issuerTokenResolver type='System.IdentityModel.Tokens.NamedKeyIssuerTokenResolver, System.IdentityModel.Tokens.JWT'>
                        <securityKey name='LocalSTS' />
                    </issuerTokenResolver>" );

            _testCases.Add( "KeyTooSmall",
                    @"<issuerTokenResolver type='System.IdentityModel.Tokens.NamedKeyIssuerTokenResolver, System.IdentityModel.Tokens.JWT'>
                        <securityKey symmetricKey = '05mPwwjMPhI==' name='LocalSTS' />
                    </issuerTokenResolver>" );

            _testCases.Add( "NameMissing",
                    @"<issuerTokenResolver type='System.IdentityModel.Tokens.NamedKeyIssuerTokenResolver, System.IdentityModel.Tokens.JWT'>
                        <securityKey symmetricKey = 'jWo8qtxA05mPwwjMPhIS7w==' />
                    </issuerTokenResolver>" );

            _testCases.Add( "EncodingWrong",
                    @"<issuerTokenResolver type='System.IdentityModel.Tokens.NamedKeyIssuerTokenResolver, System.IdentityModel.Tokens.JWT'>
                        <securityKey symmetricKey = 'jWo8qtxA05mPwwjMPhIS7w==' EncodingType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64' />
                    </issuerTokenResolver>" );

            _testCases.Add( "KeyDoesNotParse",
                    @"<issuerTokenResolver type='System.IdentityModel.Tokens.NamedKeyIssuerTokenResolver, System.IdentityModel.Tokens.JWT'>
                        <securityKey symmetricKey = '000==' />
                    </issuerTokenResolver>" );

            _testCases.Add( "EncodingRight",
                    @"<issuerTokenResolver type='System.IdentityModel.Tokens.NamedKeyIssuerTokenResolver, System.IdentityModel.Tokens.JWT'>
                        <securityKey symmetricKey = 'jWo8qtxA05mPwwjMPhIS7w==' EncodingType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary' />
                    </issuerTokenResolver>" );
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

        protected override string GetConfiguration( string testVariation )
        {
            string caseToRun = _testContextProvider.GetValue<string>( "Config" );
            return @"<system.identityModel><identityConfiguration>" + caseToRun + @"</identityConfiguration></system.identityModel>";
        }

        protected override void ValidateTestCase( string testCase )
        {
            try
            {
                IdentityConfiguration identityConfig = new IdentityConfiguration( IdentityConfiguration.DefaultServiceName );
                Assert.Fail( string.Format( "Expected Exception of type '{0}'", typeof( ConfigurationErrorsException ) ) );
            }
            catch ( Exception ex )
            {
                Assert.IsTrue( ex.GetType() == typeof( ConfigurationErrorsException ) );
            }
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "1E62250E-9208-4917-8677-0C82EFE6823E" )]
        [TestProperty( "TestType", "BVT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "NamedKeyIssuerTokenResolver BadConfig" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        [TestProperty( "Config", "{AsymmetricKey, MissingSymmetricKey, KeyTooSmall, NameMissing, EncodingWrong, KeyDoesNotParse}" )]
        public void Case()
        {
            RunTestCase( string.Empty );
        }
    }

}
