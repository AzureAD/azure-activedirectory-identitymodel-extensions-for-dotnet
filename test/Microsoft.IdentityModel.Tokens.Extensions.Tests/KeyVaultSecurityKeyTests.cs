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
using System.Reflection;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Tests;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Extensions.Tests
{
    public class KeyVaultSecurityKeyTests
    {
        private static ExpectedException AdalServiceExceptionExpected = new ExpectedException(typeExpected: typeof(TargetInvocationException), substringExpected: "Exception has been thrown by the target of an invocation.", innerTypeExpected: typeof(AdalServiceException));
        private static ExpectedException ArgumentNullExceptionExpected = new ExpectedException(typeExpected: typeof(TargetInvocationException), substringExpected: "Exception has been thrown by the target of an invocation.", innerTypeExpected: typeof(ArgumentNullException));
        private static ExpectedException KeyVaultErrorExceptionExpected = new ExpectedException(typeExpected: typeof(TargetInvocationException), substringExpected: "Exception has been thrown by the target of an invocation.", innerTypeExpected: typeof(KeyVaultErrorException));

        [Theory, MemberData(nameof(KeyVaultSecurityKeyAuthenticationCallbackTheoryData))]
        public void AuthenticationCallbackConstructorParams(KeyVaultSecurityKeyAuthenticationCallbackTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.AuthenticationCallbackConstructorParams", theoryData);

            try
            {
                _ = Activator.CreateInstance(theoryData.Type, new object[] { theoryData.KeyIdentifier, theoryData.Callback });
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
        }

        public static TheoryData<KeyVaultSecurityKeyAuthenticationCallbackTheoryData> KeyVaultSecurityKeyAuthenticationCallbackTheoryData
        {
            get => new TheoryData<KeyVaultSecurityKeyAuthenticationCallbackTheoryData>
            {
                new KeyVaultSecurityKeyAuthenticationCallbackTheoryData
                {
                    // Callback = default,
                    ExpectedException = ExpectedException.ArgumentNullException(),
                    First = true,
                    KeyIdentifier = null,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
                new KeyVaultSecurityKeyAuthenticationCallbackTheoryData
                {
                    // Callback = default,
                    ExpectedException = ExpectedException.ArgumentNullException(),
                    KeyIdentifier = string.Empty,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
                new KeyVaultSecurityKeyAuthenticationCallbackTheoryData
                {
                    Callback = null,
                    ExpectedException = ExpectedException.ArgumentNullException(),
                    // KeyIdentifier = default,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
                new KeyVaultSecurityKeyAuthenticationCallbackTheoryData
                {
                    // Callback = default,
                    ExpectedException = KeyVaultErrorExceptionExpected,
                    // KeyIdentifier = default,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
            };
        }


        [Theory, MemberData(nameof(KeyVaultSecurityKeyConfidentialClientTheoryData))]
        public void ConfidentialClientConstructorParams(KeyVaultSecurityKeyConfidentialClientTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ConfidentialClientConstructorParams", theoryData);

            try
            {
                _ = Activator.CreateInstance(theoryData.Type, new object[] { theoryData.KeyIdentifier, theoryData.ClientId, theoryData.ClientSecret });
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<KeyVaultSecurityKeyConfidentialClientTheoryData> KeyVaultSecurityKeyConfidentialClientTheoryData
        {
            get => new TheoryData<KeyVaultSecurityKeyConfidentialClientTheoryData>
            {
                new KeyVaultSecurityKeyConfidentialClientTheoryData
                {
                    // ClientId = default,
                    // ClientSecret = default,
                    ExpectedException = ArgumentNullExceptionExpected,
                    First = true,
                    KeyIdentifier = null,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
                new KeyVaultSecurityKeyConfidentialClientTheoryData
                {
                    // ClientId = default,
                    // ClientSecret = default,
                    ExpectedException = ArgumentNullExceptionExpected,
                    KeyIdentifier = string.Empty,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
                new KeyVaultSecurityKeyConfidentialClientTheoryData
                {
                    ClientId = null,
                    // ClientSecret = default,
                    ExpectedException = ArgumentNullExceptionExpected,
                    // KeyIdentifier = default,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
                new KeyVaultSecurityKeyConfidentialClientTheoryData
                {
                    ClientId = string.Empty,
                    /*
                    ClientSecret = default,
                    */
                    ExpectedException = ArgumentNullExceptionExpected,
                    // KeyIdentifier = default,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
                new KeyVaultSecurityKeyConfidentialClientTheoryData
                {
                    // ClientId = default,
                    ClientSecret = null,
                    ExpectedException = ArgumentNullExceptionExpected,
                    // KeyIdentifier = default,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
                new KeyVaultSecurityKeyConfidentialClientTheoryData
                {
                    // ClientId = default,
                    ClientSecret = string.Empty,
                    ExpectedException = ArgumentNullExceptionExpected,
                    // KeyIdentifier = default,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
                new KeyVaultSecurityKeyConfidentialClientTheoryData
                {
                    // ClientId = default,
                    // ClientSecret = default,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    // KeyIdentifier = default,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
            };
        }

        [Theory, MemberData(nameof(KeyVaultSecurityKeyManagedServiceIdentityTheoryData))]
        public void ManagedServiceIdentityConstructorParams(KeyVaultSecurityKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ManagedServiceIdentityConstructorParams", theoryData);

            try
            {
                _ = Activator.CreateInstance(theoryData.Type, new object[] { theoryData.KeyIdentifier });
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
        }

        public static TheoryData<KeyVaultSecurityKeyManagedServiceIdentityTheoryData> KeyVaultSecurityKeyManagedServiceIdentityTheoryData
        {
            get => new TheoryData<KeyVaultSecurityKeyManagedServiceIdentityTheoryData>
            {
                new KeyVaultSecurityKeyManagedServiceIdentityTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException(),
                    First = true,
                    KeyIdentifier = null,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
                new KeyVaultSecurityKeyManagedServiceIdentityTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException(),
                    KeyIdentifier = string.Empty,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
                new KeyVaultSecurityKeyManagedServiceIdentityTheoryData
                {
                    ExpectedException = KeyVaultErrorExceptionExpected,
                    // KeyIdentifier = default,
                    TestId = typeof(KeyVaultSecurityKey).FullName,
                    Type = typeof(KeyVaultSecurityKey),
                },
            };
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
