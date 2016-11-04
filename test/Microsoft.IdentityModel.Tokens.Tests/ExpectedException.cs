//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// When a test case throws an exception, this class helps to determine if the exception is as exptected.
    /// Really just a helper for wrapping things.
    /// </summary>
    public class ExpectedException
    {
        public ExpectedException(Type typeExpected = null, string substringExpected = null, Type innerTypeExpected = null, Dictionary<string, object> propertiesExpected = null)
        {
            IgnoreInnerException = false;
            InnerTypeExpected = innerTypeExpected;
            SubstringExpected = substringExpected;
            TypeExpected = typeExpected;
            PropertiesExpected = propertiesExpected;
        }

        public static bool DefaultVerbose { get; set; } = false;

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

        public static ExpectedException SecurityTokenDecryptionFailedException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenDecryptionFailedException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

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
            if (TypeExpected == null && InnerTypeExpected != null)
            {
                HandleError("(TypeExpected == null && InnerTypeExpected != null. TypeExpected == null && InnerTypeExpected != null.", errors);
                return;
            }

            if (TypeExpected == null)
            {
                HandleError("exception != null, expectedException.TypeExpected == null.\nexception: " + exception, errors);
                return;
            }

            if (exception == null)
            {
                HandleError("exception == null, expectedException.TypeExpected != null.\nexpectedException.TypeExpected: " + TypeExpected, errors);
                return;
            }

            if (exception.GetType() != TypeExpected)
            {
                HandleError("exception.GetType() != expectedException.TypeExpected:\nexception.GetType(): " + exception.GetType() + "\nexpectedException.TypeExpected: " + TypeExpected, errors);
                return;
            }

            if (!string.IsNullOrWhiteSpace(SubstringExpected) && !exception.Message.Contains(SubstringExpected))
            {
                HandleError("!exception.Message.Contains(SubstringExpected).\nexception.Message: " + exception.Message + "\nexpectedException.SubstringExpected: " + SubstringExpected, errors);
                return;
            }

            if (exception.InnerException != null && InnerTypeExpected == null)
            {
                HandleError("exception.InnerException != null && expectedException.InnerTypeExpected == null.\nexception.InnerException: " + exception.InnerException, errors);
                return;
            }

            if (exception.InnerException == null && InnerTypeExpected != null)
            {
                HandleError("exception.InnerException == null, expectedException.InnerTypeExpected != null.\nexpectedException.InnerTypeExpected: " + InnerTypeExpected, errors);
                return;
            }

            if ((InnerTypeExpected != null) && (exception.InnerException.GetType() != InnerTypeExpected ) && !IgnoreInnerException)
            {
                HandleError("exception.InnerException != expectedException.InnerTypeExpected." + "\nexception.InnerException: '" + exception.InnerException + "\nInnerTypeExpected: " + InnerTypeExpected, errors);
            }

            if (PropertiesExpected != null && PropertiesExpected.Count > 0)
            { 
                foreach (KeyValuePair<string, object> property in PropertiesExpected)
                {
                    PropertyInfo propertyInfo = TypeExpected.GetProperty(property.Key);
                    if (propertyInfo == null)
                    {
                        HandleError("exception type " + TypeExpected + " does not have expected property " + property.Key, errors);
                    }
                    object runtimeValue = propertyInfo.GetValue(exception);

                    bool expectedTypeIsNullable = propertyInfo.PropertyType.GetTypeInfo().IsGenericType && propertyInfo.PropertyType.GetGenericTypeDefinition() == typeof(Nullable<>);
                    Type expectedTypeNonNullable = expectedTypeIsNullable ? propertyInfo.PropertyType.GetGenericArguments()[0] : propertyInfo.PropertyType;

                    if (runtimeValue != null && runtimeValue.GetType() != expectedTypeNonNullable && !expectedTypeNonNullable.IsAssignableFrom(runtimeValue.GetType()))
                    {
                        HandleError("exception type " + TypeExpected + " does not match the expected property " + property.Key + " type.\nexpected type: " + expectedTypeNonNullable + ", actual type: " + runtimeValue.GetType(), errors);
                    }

                    if (runtimeValue != property.Value && 
                        ((runtimeValue != null && !runtimeValue.Equals(property.Value)) ||
                         (property.Value != null && !property.Value.Equals(runtimeValue))))
                    {
                        HandleError("exception type " + TypeExpected + " doesn't have the expected property value " + property.Key + " value.\nexpected value: " + property.Value + ", actual value: " + runtimeValue, errors);
                    }
                }
            }

            if (DefaultVerbose || Verbose)
                Console.WriteLine(Environment.NewLine + "Exception displayed to user: " + Environment.NewLine + Environment.NewLine + exception);
        }

        public void ProcessNoException(List<string> errors = null)
        {
            if (TypeExpected != null)
            {
                if (errors != null)
                    errors.Add("expectedException.TypeExpected != null: " + TypeExpected);
                else
                    Assert.True(false, "expectedException.TypeExpected != null: '" + TypeExpected);
            }
        }

        public void ProcessNoException(CompareContext context)
        {
            if (TypeExpected != null)
                context.Diffs.Add("expectedException.TypeExpected != null: " + TypeExpected);
        }

        private static void HandleError(string err, List<string> errors )
        {
            if (errors != null)
                errors.Add(err);
            else
                Assert.True(false, err);
        }

        public static ExpectedException SecurityTokenEncryptionKeyNotFoundException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenEncryptionKeyNotFoundException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenEncryptionFailedException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenEncryptionFailedException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenException(string substringExpected = null, Type innertypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenException), substringExpected: substringExpected, innerTypeExpected: innertypeExpected);
        }

        public static ExpectedException SecurityTokenExpiredException(string substringExpected = null, Type innerTypeExpected = null, Dictionary<string, object> propertiesExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenExpiredException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected, propertiesExpected: propertiesExpected);
        }

        public static ExpectedException SecurityTokenInvalidAudienceException(string substringExpected = null, Type innerTypeExpected = null, Dictionary<string, object> propertiesExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidAudienceException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected, propertiesExpected: propertiesExpected);
        }

        public static ExpectedException SecurityTokenInvalidIssuerException(string substringExpected = null, Type innerTypeExpected = null, Dictionary<string, object> propertiesExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidIssuerException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected, propertiesExpected: propertiesExpected);
        }

        public static ExpectedException SecurityTokenInvalidLifetimeException(string substringExpected = null, Type innerTypeExpected = null, Dictionary<string, object> propertiesExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidLifetimeException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected, propertiesExpected: propertiesExpected);
        }

        public static ExpectedException SecurityTokenInvalidSignatureException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidSignatureException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public static ExpectedException SecurityTokenNoExpirationException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenNoExpirationException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }                

        public static ExpectedException SecurityTokenNotYetValidException(string substringExpected = null, Type innerTypeExpected = null, Dictionary<string, object> propertiesExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenNotYetValidException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected, propertiesExpected: propertiesExpected);
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

        public static ExpectedException SecurityTokenInvalidSigningKeyException(string substringExpected = null, Type innerTypeExpected = null, Dictionary<string, object> propertiesExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(SecurityTokenInvalidSigningKeyException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected, propertiesExpected: propertiesExpected);
        }

        public static ExpectedException KeyWrapUnwrapException(string substringExpected = null, Type innerTypeExpected = null)
        {
            return new ExpectedException(typeExpected: typeof(KeyWrapUnwrapException), substringExpected: substringExpected, innerTypeExpected: innerTypeExpected);
        }

        public bool IgnoreInnerException { get; set; }

        public Type InnerTypeExpected { get; set; }

        public Dictionary<string, object> PropertiesExpected { get; set; }

        public string SubstringExpected { get; set; }

        public Type TypeExpected { get; set; }

        public bool Verbose { get; set; } = false;
    }
}
