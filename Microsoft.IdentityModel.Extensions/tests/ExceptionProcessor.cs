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
using System.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// When a test case throws an exception, this class helps to determine if the exception is as exptected.
    /// Really just a helper for wrapping things.
    /// </summary>
    public class ExceptionProcessor
    {
        public ExceptionProcessor(Type typeExpected = null, string substringExpected = null, Type innerTypeExpected = null)
        {
            TypeExpected = typeExpected;
            SubstringExpected = substringExpected;
            InnerTypeExpected = innerTypeExpected;
        }

        public static ExceptionProcessor ArgumentException(string substringExpected = null, Type inner = null)
        {
            return new ExceptionProcessor(typeExpected: typeof(ArgumentException), substringExpected: substringExpected, innerTypeExpected: inner);
        }
        public static ExceptionProcessor ArgumentOutOfRangeException(string substringExpected = null, Type inner = null)
        {
            return new ExceptionProcessor(typeExpected: typeof(ArgumentOutOfRangeException), substringExpected: substringExpected, innerTypeExpected: inner);
        }

        public static ExceptionProcessor ArgumentNullException(string substringExpected = null, Type inner = null)
        {
            return new ExceptionProcessor(typeExpected: typeof(ArgumentNullException), substringExpected: substringExpected, innerTypeExpected: inner); 
        }

        public static ExceptionProcessor ConfigurationErrorsException(string substringExpected = null, Type inner = null)
        {
            return new ExceptionProcessor(typeExpected: typeof(ConfigurationErrorsException), substringExpected: substringExpected, innerTypeExpected: inner);
        }
        public Type InnerTypeExpected { get; set; }

        public static ExceptionProcessor InvalidOperationException(string substringExpected = null, Type inner = null, string contains = null)
        {
            return new ExceptionProcessor(typeExpected: typeof(InvalidOperationException), substringExpected: substringExpected, innerTypeExpected: inner);
        }

        public static ExceptionProcessor NoExceptionExpected 
        { 
            get 
            { 
                return new ExceptionProcessor(); 
            } 
        }

        public static ExceptionProcessor ObjectDisposedException 
        { 
            get 
            {
                return new ExceptionProcessor(typeExpected: typeof(ObjectDisposedException)); 
            } 
        }

        public void ProcessException(Exception exception)
        {
            if (TypeExpected == null)
            {
                Assert.IsNull(exception, "Did NOT expect exception, caught: '" + exception + "'");
            }
            else
            {
                Assert.IsNotNull(exception, "Expected exception of type: '" + TypeExpected + " 'exception' parameter was null");
                Assert.AreEqual(TypeExpected, exception.GetType(), "Expected exception of type: '" + TypeExpected + "', caught: '" + exception + "'");
            }

            if (InnerTypeExpected == null)
            {
                if (exception != null)
                {
                    Assert.IsNull(exception.InnerException, "InnerException is null, but caught an exception where expection.Inner != null. Execption: '" + exception + "'.");
                }
            }
            else
            {
                Assert.IsNotNull(exception, "InnerException is NOT null, but exception is null. InnerTypeExpected: '" + InnerTypeExpected + ".");
                Assert.IsNotNull(exception.InnerException, "'exception.InnerException' was NULL, expeced to find: '" + InnerTypeExpected + "'");
                Assert.AreEqual(InnerTypeExpected, exception.InnerException.GetType(), "InnerExceptions didn't match on type, InnerTypeExpected: '" + InnerTypeExpected + "', exception.InnerException: '" + exception.InnerException + "'");
            }

#if _Verbose
            Console.WriteLine("Exception displayed to user:\n\n '{ +" + exception + "'}");
#endif
        }

        public void ProcessNoException()
        {
            if (TypeExpected != null)
            {
                Assert.Fail("TypeExpected: '" + TypeExpected + "'.");
            }
        }

        public static ExceptionProcessor SecurityTokenException(string substringExpected = null, Type innertypeExpected = null)
        {
            return new ExceptionProcessor(typeExpected: typeof(SecurityTokenException), substringExpected: substringExpected, innerTypeExpected: innertypeExpected);
        }

        public static ExceptionProcessor SecurityTokenValidationException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExceptionProcessor(typeExpected: typeof(SecurityTokenValidationException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }                

        public string SubstringExpected { get; set; }

        public Type TypeExpected { get; set; }
    }
}
