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

#define  _Verbose

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Configuration;
using System.Globalization;
using System.IdentityModel;
using System.IdentityModel.Tokens;
using System.IO;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// When a test case throws an exception, this class helps to determine if the exception is as exptected.
    /// Really just a helper for wrapping things.
    /// </summary>
    public class ExpectedException
    {
        public ExpectedException(Type typeExpected = null, string substringExpected = null, Type innerTypeExpected = null)
        {
            TypeExpected = typeExpected;
            SubstringExpected = substringExpected;
            InnerTypeExpected = innerTypeExpected;
        }

        public static ExpectedException ArgumentException(string substringExpected = null, Type inner = null)
        {
            return new ExpectedException(typeExpected: typeof(ArgumentException), substringExpected: substringExpected, innerTypeExpected: inner);
        }
        public static ExpectedException ArgumentOutOfRangeException(string substringExpected = null, Type inner = null)
        {
            return new ExpectedException(typeExpected: typeof(ArgumentOutOfRangeException), substringExpected: substringExpected, innerTypeExpected: inner);
        }

        public static ExpectedException ArgumentNullException(string substringExpected = null, Type inner = null)
        {
            return new ExpectedException(typeExpected: typeof(ArgumentNullException), substringExpected: substringExpected, innerTypeExpected: inner); 
        }

        public static ExpectedException ConfigurationErrorsException(string substringExpected = null, Type inner = null)
        {
            return new ExpectedException(typeExpected: typeof(ConfigurationErrorsException), substringExpected: substringExpected, innerTypeExpected: inner);
        }
        public Type InnerTypeExpected { get; set; }

        public static ExpectedException InvalidOperationException(string substringExpected = null, Type inner = null, string contains = null)
        {
            return new ExpectedException(typeExpected: typeof(InvalidOperationException), substringExpected: substringExpected, innerTypeExpected: inner);
        }

        public static ExpectedException IOException(string substringExpected = null, Type inner = null, string contains = null)
        {
            return new ExpectedException(typeExpected: typeof(IOException), substringExpected: substringExpected, innerTypeExpected: inner);
        }

        public static ExpectedException NoExceptionExpected 
        { 
            get 
            { 
                return new ExpectedException(); 
            } 
        }

        public static ExpectedException ObjectDisposedException 
        { 
            get 
            {
                return new ExpectedException(typeExpected: typeof(ObjectDisposedException)); 
            } 
        }

        public void ProcessException(Exception exception)
        {
            // no need to check unit test asertions.
            if (typeof(Microsoft.VisualStudio.TestTools.UnitTesting.AssertFailedException) == exception.GetType())
            {
                throw exception;
            }

            if (TypeExpected == null)
            {
                Assert.IsNull(exception, "Did NOT expect exception, caught: '" + exception + "'");
            }
            else
            {
                Assert.IsNotNull(exception, "Expected exception of type: '" + TypeExpected + " 'exception' parameter was null");
                Assert.AreEqual(TypeExpected, exception.GetType(), "Expected exception of type: '" + TypeExpected + "', caught: '" + exception + "'");
                if (!string.IsNullOrWhiteSpace(SubstringExpected))
                {
                    Assert.IsTrue(exception.ToString().Contains(SubstringExpected), string.Format(CultureInfo.InvariantCulture, "Substring expected: '{0}', exception: '{1}'", SubstringExpected, exception.ToString()));
                }
            }

            if (InnerTypeExpected == null)
            {
                if (exception != null && exception.InnerException != null)
                {
                    Assert.Fail("EXPECTED InnerException is null, but caught an exception where expection.InnerException != null. \nInnerExecption:\n" + exception.InnerException + "\nException:\n" + exception);
                }
            }
            else
            {
                Assert.IsNotNull(exception, "InnerException is NOT null, but EXPECTED InnerException is null. InnerTypeExpected: '" + InnerTypeExpected + ".");
                Assert.IsNotNull(exception.InnerException, "'exception.InnerException' was NULL, expeced to find: '" + InnerTypeExpected + "'");
                Assert.AreEqual(InnerTypeExpected, exception.InnerException.GetType(), "InnerExceptions didn't match on type, InnerTypeExpected:\n '" + InnerTypeExpected + "', exception.InnerException: '" + exception.InnerException + "'");
            }

#if _Verbose
            Console.WriteLine("Exception displayed to user:\n\n '{ +" + exception + "'}");
#endif
        }

        public void ProcessNoException()
        {
            if (TypeExpected != null)
            {
                Assert.Fail("Exception was expected, type: '" + TypeExpected + "'.");
            }
        }

        public static ExpectedException SecurityTokenException(string substringExpected = null, Type innertypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenException), substringExpected: substringExpected, innerTypeExpected: innertypeExpected);
        }

        public static ExpectedException SecurityTokenInvalidAudienceException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidAudienceException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenInvalidLifetimeException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidLifetimeException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }                

        public static ExpectedException SecurityTokenInvalidIssuerException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidIssuerException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenInvalidSignatureException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidSignatureException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenSignatureKeyNotFoundException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenSignatureKeyNotFoundException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenValidationException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenValidationException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }


        public static ExpectedException SignatureVerificationFailedException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SignatureVerificationFailedException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }                

        public string SubstringExpected { get; set; }

        public Type TypeExpected { get; set; }
    }
}
