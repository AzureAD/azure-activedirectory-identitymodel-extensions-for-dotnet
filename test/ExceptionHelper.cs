//----------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//----------------------------------------------------------------

#define  _Verbose

using System;
using System.Configuration;
using System.Diagnostics;
using System.Globalization;
using System.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace System.IdentityModel.Test
{
    public class ExpectedException
    {
        public static ExpectedException Null { get { return new ExpectedException(); } }
        public static ExpectedException ArgNull { get { return new ExpectedException( thrown: typeof( ArgumentNullException ) ); } }
        public static ExpectedException ArgEx( string id = null, Exception inner = null )
        {
            return new ExpectedException( thrown: typeof( ArgumentException ), id: id, inner: inner );
        }

        public static ExpectedException ArgRange( string id = null, Exception inner = null )
        {
            return new ExpectedException( thrown: typeof( ArgumentOutOfRangeException ), id: id, inner: inner );
        }

        public static ExpectedException Aud( string id = null, Exception inner = null, string contains = null )
        {
            return new ExpectedException( thrown: typeof( AudienceUriValidationFailedException ), id: id, inner: inner );
        }

        public static ExpectedException Config( string id = null, Exception inner = null )
        {
            return new ExpectedException( thrown: typeof( ConfigurationErrorsException ), id: id, inner: inner );
        }

        public static ExpectedException InvalidOp( string id = null, Exception inner = null, string contains = null )
        {
            return new ExpectedException( thrown: typeof( InvalidOperationException ), id: id, inner: inner );
        }

        public static ExpectedException Sec( string id = null, Exception inner = null, string contains = null )
        {
            return new ExpectedException( thrown: typeof( SecurityTokenException ), id: id, inner: inner );
        }

        public static ExpectedException SecVal( string id = null, Exception inner = null, string contains = null )
        {
            return new ExpectedException( thrown: typeof( SecurityTokenValidationException ), id: id, inner: inner );
        }
        
        public static ExpectedException ObjDisp { get { return new ExpectedException( thrown: typeof( ObjectDisposedException ) ); } }

        public ExpectedException( Type thrown = null, string id = null, Exception inner = null )
        {
            Thrown = thrown;
            Id = id;
            Inner = inner;
        }

        public Type Thrown { get; set; }
        public string Id { get; set; }
        public Exception Inner { get; set; }

        public static bool ProcessNoException( ExpectedException exceptionExpected )
        {
            bool retval = false;

            if ( exceptionExpected != null && exceptionExpected.Thrown != null )
            {
                Assert.Fail( "Expected Exception of type: '{0}'", exceptionExpected.Thrown );               
            }

            return retval;
        }

        public static bool ProcessException( ExpectedException exceptionExpected, Exception ex )
        {
            bool retval = false;

            Assert.IsFalse( ( exceptionExpected == null || exceptionExpected.Thrown == null ) && ex != null , string.Format( "DID NOT expect exception, caught: '{0}'", ex ) );
            Assert.IsFalse( ex.GetType() != exceptionExpected.Thrown , string.Format( "Expected exception of type: '{0}', caught: '{1}'", exceptionExpected.Thrown, ex ) );
            Assert.IsFalse( !string.IsNullOrWhiteSpace( exceptionExpected.Id ) && !ex.Message.Contains( exceptionExpected.Id ) , string.Format( "Expected Exception.Message to contain: '{0}', caught: '{1}'", exceptionExpected.Id, ex ) );

            if ( exceptionExpected.Inner != null )
            {
                Assert.IsFalse( ex.InnerException == null , string.Format( "Expected InnerException was not found: '{0}' ", exceptionExpected.Inner ) );
                Assert.IsFalse( ex.InnerException.GetType() != exceptionExpected.Inner.GetType() , string.Format( "Expected InnerException: '{0}', was ex.InnerException: '{1}'", exceptionExpected.Inner, ex.InnerException ) );
            }

            #if _Verbose
                Console.WriteLine( string.Format( "Exception displayed to user:\n\n'{0}'\n", ex ) );
            #endif

            return retval;
        }        
    }
}
