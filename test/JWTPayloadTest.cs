//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IdentityModel.Tokens;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class JwtPayloadTests
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;


        public TestContext TestContext { get; set; }


        [ClassInitialize]
        public static void ClassSetup( TestContext testContext )
        {
            // Start local STS
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            // Stop local STS
        }

        [TestInitialize]
        public void Initialize()
        {
            _testContextProvider = new TestContextProvider( TestContext );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "F443747C-5AA1-406D-B0FE-53152CA92DA3" )]
        [TestProperty( "TestType", "CIT" )]
        [TestProperty( "Environments", "ACSDevBox" )]
        [Description( "Tests adding non-strings as 'exp'" )]
        [Priority( 0 )]
        [Owner( "BrentSch" )]
        [TestProperty( "DisciplineOwner", "Dev" )]
        [TestProperty( "Feature", "ACS/AAL" )]
        [TestProperty( "Framework", "TAEF" )]
        public void JwtPalyoad_ObjectClaims()
        {
            JwtPayload jwtPayload = new JwtPayload();
            Int32? time = 10000;
            jwtPayload.Add( "exp", time );
            DateTime payloadTime = EpochTime.DateTime( time.Value );
            DateTime payloadValidTo = jwtPayload.ValidTo;

            Assert.IsFalse(EpochTime.DateTime(time.Value) != jwtPayload.ValidTo, "EpochTime.DateTime( time ) != jwtPayload.ValidTo");

            Int32? expirationTime = jwtPayload.Expiration;
            Assert.IsTrue(expirationTime == time, "expirationTime != time");
        }
    }
}