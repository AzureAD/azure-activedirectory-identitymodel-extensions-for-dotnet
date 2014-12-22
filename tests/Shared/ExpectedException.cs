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

using System.Globalization;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using Xunit;

namespace System.IdentityModel.Test
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

        public static ExpectedException CryptographicException(string substringExpected = null, Type inner = null)
        {
            return new ExpectedException(typeExpected: typeof(CryptographicException), substringExpected: substringExpected, innerTypeExpected: inner);
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

        public void ProcessException(Exception exception, List<string> errors = null)
        {
            string err;

            if (TypeExpected == null)
            {
                err = "Did NOT expect exception, caught: '" + exception + "'";
                if (errors != null)
                    errors.Add(err);
                else
                    Assert.True(false, err);
            }
            else
            {
                if (exception == null)
                {
                    err = "Expected exception of type: '" + TypeExpected + " 'exception' parameter was null";
                    if (errors != null)
                        errors.Add(err);
                    else
                        Assert.True(false, err);
                }

                if (TypeExpected != exception.GetType())
                {
                    err = "Expected exception of type: '" + TypeExpected + "', caught: '" + exception + "'";
                    if (errors != null)
                        errors.Add(err);
                    else
                        Assert.True(false, err);
                }

                if (!string.IsNullOrWhiteSpace(SubstringExpected))
                {
                    if (!exception.Message.Contains(SubstringExpected))
                    {
                        err = string.Format("Substring expected: '{0}', exception: '{1}'", SubstringExpected, exception.ToString());
                        if (errors != null)
                            errors.Add(err);
                        else
                            Assert.True(false, err);
                    }
                }
            }

            if (InnerTypeExpected == null)
            {
                if (exception != null && exception.InnerException != null)
                {
                    err = "EXPECTED InnerException is null, but caught an exception where expection.InnerException != null. \nInnerExecption:\n" + exception.InnerException + "\nException:\n" + exception;
                    if (errors != null)
                        errors.Add(err);
                    else
                        Assert.True(false, err);
                }
            }
            else
            {
                if (exception.InnerException == null)
                {
                    err = "exception.InnerException is NOT null, but EXPECTED InnerException is null. InnerTypeExpected: '" + InnerTypeExpected + ".";
                    if (errors != null)
                        errors.Add(err);
                    else
                        Assert.True(false, err);
                }

                if (InnerTypeExpected != exception.InnerException.GetType())
                {
                    err = "InnerExceptions didn't match on type, InnerTypeExpected:\n '" + InnerTypeExpected + "', exception.InnerException: '" + exception.InnerException + "'";
                    if (errors != null)
                        errors.Add(err);
                    else
                        Assert.True(false, err);
                }
            }

#if _Verbose
            Console.WriteLine(Environment.NewLine + "Exception displayed to user: " + Environment.NewLine + Environment.NewLine + exception);
#endif
        }

        public void ProcessNoException(List<string> errors = null)
        {
            if (TypeExpected != null)
            {
                if (errors != null)
                    errors.Add("Exception was expected, type: '" + TypeExpected + "'.");
                else
                    Assert.True(false, "Exception was expected, type: '" + TypeExpected + "'.");
            }
        }

        public static ExpectedException SecurityTokenException(string substringExpected = null, Type innertypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenException), substringExpected: substringExpected, innerTypeExpected: innertypeExpected);
        }

        public static ExpectedException SecurityTokenExpiredException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenExpiredException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }
        public static ExpectedException SecurityTokenInvalidAudienceException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidAudienceException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenInvalidIssuerException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidIssuerException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenInvalidLifetimeException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidLifetimeException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenInvalidSignatureException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidSignatureException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SignatureVerificationFailedException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SignatureVerificationFailedException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenNoExpirationException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenNoExpirationException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }                

        public static ExpectedException SecurityTokenNotYetValidException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenNotYetValidException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenReplayAddFailed(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenReplayAddFailedException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenReplayDetected(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenReplayDetectedException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }                

        public static ExpectedException SecurityTokenSignatureKeyNotFoundException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenSignatureKeyNotFoundException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenValidationException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenValidationException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public string SubstringExpected { get; set; }

        public Type TypeExpected { get; set; }
    }
}
