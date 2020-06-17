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
using System.Security.Claims;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Saml.Tests;
using Microsoft.IdentityModel.Xml;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Saml2.Tests
{
    public class Saml2EncryptionTests
    {
#if NET_CORE_3_0
        #region EncryptedAssertion
        [Theory, MemberData(nameof(AccessEncryptedAssertionTheoryData))]
        public void AccessEncryptedAssertion(Saml2TheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.AccessEncryptedAssertion", theoryData);

            try
            {
                var token = theoryData.Handler.ReadSaml2Token(theoryData.Token);

                IdentityComparer.AreEqual(token.Assertion.Encrypted, true, context); // saml2 assertion is encrypted hence Assertion.Encrypted should be True

                if (string.IsNullOrEmpty(token.Assertion.EncryptedAssertion))
                    context.Diffs.Add("!Assertion.EncryptedAssertion string should not be empty if Saml2Assertion.Encrypted == True");

                var result = token.Assertion.GetType().GetProperty(theoryData.PropertyBag["AssertionPropertyName"].ToString()).GetValue(token.Assertion, null);

                IdentityComparer.AreEqual(result, theoryData.PropertyBag["AssertionPropertyExpectedValue"], context);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex.InnerException, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> AccessEncryptedAssertionTheoryData
        {
            get
            {
                var theoryData = new TheoryData<Saml2TheoryData>();

                theoryData.Add(new Saml2TheoryData
                {
                    First = true,
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Advice" }, { "AssertionPropertyExpectedValue", null } },
                    TestId = "EncryptedAssertion_Access_Advice",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Conditions" }, { "AssertionPropertyExpectedValue", null } },
                    TestId = "EncryptedAssertion_Access_Conditions",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Id" }, { "AssertionPropertyExpectedValue", null } },
                    TestId = "EncryptedAssertion_Access_Id",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "IssueInstant" }, { "AssertionPropertyExpectedValue", DateTime.MinValue } },
                    TestId = "EncryptedAssertion_Access_IssueInstantConditions",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Issuer" }, { "AssertionPropertyExpectedValue", null } },
                    TestId = "EncryptedAssertion_Access_Issuer",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "InclusiveNamespacesPrefixList" }, { "AssertionPropertyExpectedValue", null } },
                    TestId = "EncryptedAssertion_Access_InclusiveNamespacesPrefixList",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "SigningCredentials" }, { "AssertionPropertyExpectedValue", null } },
                    TestId = "EncryptedAssertion_Access_SigningCredentials",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Subject" }, { "AssertionPropertyExpectedValue", null } },
                    TestId = "EncryptedAssertion_Access_Subject",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Statements" }, { "AssertionPropertyExpectedValue", null } },
                    TestId = "EncryptedAssertion_Access_Statements",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Signature" }, { "AssertionPropertyExpectedValue", null } },
                    TestId = "EncryptedAssertion_Access_Signature",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Version" }, { "AssertionPropertyExpectedValue", "2.0" } },
                    TestId = "EncryptedAssertion_Access_Version",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "EncryptingCredentials" }, { "AssertionPropertyExpectedValue", null} },
                    TestId = "EncryptedAssertion_Access_EncryptingCredentials",
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ReadEncryptedTokenTheoryData))]
        public void ReadEncryptedToken(Saml2TheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadEncryptedToken", theoryData);

            try
            {
                var saml2EncryptedToken = theoryData.Handler.ReadSaml2Token(theoryData.Token);
                IdentityComparer.AreEqual(saml2EncryptedToken.Assertion.Encrypted, true, context); // token should be encrypted

                if (string.IsNullOrEmpty(saml2EncryptedToken.Assertion.EncryptedAssertion)) // if token is encrypted, EncryptedAssertion string should not be empty
                    context.Diffs.Add("!Assertion.EncryptedAssertion string should not be empty if Saml2Assertion.Encrypted == True");

                theoryData.Handler.ValidateToken(theoryData.Token, theoryData.ValidationParameters, out SecurityToken validatedToken); // validate/decrypt token

                IdentityComparer.AreEqual(((Saml2SecurityToken)validatedToken).Assertion.Encrypted, false, context); // token should be decrypted

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ReadEncryptedTokenTheoryData
        {
            get
            {
                // list keys
                var signingKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256;
                var sessionKey = KeyingMaterial.DefaultSymmetricSecurityKey_128;
                var wrongSessionKey = KeyingMaterial.DefaultSymmetricSecurityKey_192;
                var wrongKeyWrapKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA512;
                var cert = KeyingMaterial.DefaultCert_2048;

                var signingCredentials_Valid = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
                var encryptingCredentials_PreSharedSessionKey_Valid = new EncryptingCredentials(sessionKey, SecurityAlgorithms.Aes128Gcm);
                var encryptingCredentials_X509_Valid = new X509EncryptingCredentials(cert);

                //SET HELPER CRYPTO PROVIDER FACTORY - remove when AES-GCM is released and supported
                encryptingCredentials_PreSharedSessionKey_Valid.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_X509_Valid.CryptoProviderFactory = new AesGcmProviderFactory();

                var tokenDescriptor_PreSharedSessionKey_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_PreSharedSessionKey_Valid);
                var tokenDescriptor_KeyWrap_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_X509_Valid);

                var tokenHandler = new Saml2SecurityTokenHandler();
                var theoryData = new TheoryData<Saml2TheoryData>();

                theoryData.Add(new Saml2TheoryData
                {
                    First = true,
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_ExtraSpaces_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_ExtraSpaces_Valid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_DifferentPrefixes_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_DifferentPrefixes_Valid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_Valid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_DataReference_AsNonEmptyElement_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_DataReference_AsNonEmptyElement_Valid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_DigestMethod_AsNonEmptyElement_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_DigestMethod_AsNonEmptyElement_Valid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_EncryptionMethod_AsNonEmptyElement_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_EncryptionMethod_AsNonEmptyElement_Valid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_KeyInfoAsEmptyElement_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_KeyInfoAsEmptyElement_Valid),
                });

                // Bad content. For AES-GCM: IV takes 12 bytes, Auth Tag 16 bytes => Cipher-text size is less than 1
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenDecryptionFailedException), "IDX10620: Decryption failed."),
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadContent_Invalid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadContent_Invalid),
                });

                // namespace missing
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoXencNamespace_Invalid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoXencNamespace_Invalid),
                });

                // namespace missing or as expected
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_Invalid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_Invalid),
                });

                // namespace missing or as expected
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_v2_Invalid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_v2_Invalid),
                });

                // namespace missing or as expected
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_v3_Invalid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_v3_Invalid),
                });

                // Additional KeyInfo clauses (skipped while reading) should result with a valid EncryptedAssertion
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_AdditionalKeyInfoClauseValid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_AdditionalKeyInfoClauseValid),
                });

                // EncryptedKey element embedded in EncryptedData element is not supported
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_EmbeddedEncryptedKey_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30030"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_EmbeddedEncryptedKey_Invalid),
                });

                // Key-wrap algorithm not supported
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_Alg_Invalid,
                    ExpectedException = new ExpectedException(typeof(System.NotSupportedException), "IDX10661"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_Alg_Invalid),
                });

                // Encryption algorithm is not provided - currently not supported
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptionAlgorithm_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13611"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptionAlgorithm_Invalid),
                });

                // Encryption algorithm is not provided - currently not supported
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptionAlgorithm_v2_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13611"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptionAlgorithm_v2_Invalid),
                });

                // Encryption algorithm is not provided - currently not supported
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoEncryptionAlgorithm_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13611"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoEncryptionAlgorithm_Invalid),
                });

                // Encryption algorithm is not provided - currently not supported
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoEncryptionAlgorithm_v2_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13611"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoEncryptionAlgorithm_v2_Invalid),
                });

                // DataReference element is not referencing the EncryptedData element
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadDataReference_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13616"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadDataReference_Invalid),
                });

                // DataReference element is correct, but referencing EncryptedData element has no Id
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_GoodDataReference_EncryptedData_NoId_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13615"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_GoodDataReference_EncryptedData_NoId_Invalid),
                });

                // EncryptedData element has a RetreivalUri but the is no EncryptedKey with that Id
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadRetrievalUri_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13618"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadRetrievalUri_Invalid),
                });

                // EncryptedData element has a correct RetreivalUri but the is EncryptedKey has no Id
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadRetrievalUri_NoKeyId_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13617"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadRetrievalUri_NoKeyId_Invalid),
                });

                // Type of EncryptedData is not correct
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadEncryptedDataType_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13613"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadEncryptedDataType_Invalid),
                });

                // Type of EncryptedKey is not correct
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadEncryptedKeyType_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13614"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadEncryptedKeyType_Invalid),
                });

                // There is no CipherValue element
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoCipherValue_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoCipherValue_Invalid),
                });

                // There is no CipherData element
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoCipherData_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoCipherData_Invalid),
                });

                // There is no EncryptedData element
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptedData_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException)),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptedData_Invalid),
                });

                // There is no CipherValue element (content)
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoCipherValue_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoCipherValue_Invalid),
                });

                // There is no CipherValue element (KeyWrap)
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoCipherValue_v2_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoCipherValue_v2_Invalid),
                });

                // incorrect keywrap key
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, wrongKeyWrapKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_Valid,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenKeyWrapException), "IDX10659"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_Valid) + "_wrong_keyunwrap_key",
                });

                // some prefixes are missing/wrong
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_PrefixMissing_Invalid,
                    ExpectedException = new ExpectedException(typeof(System.Xml.XmlException)),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_PrefixMissing_Invalid),
                });

                // namespace is missing/wrong
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NamespaceMissing_Invalid,
                    ExpectedException = new ExpectedException(typeof(System.Xml.XmlException)),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NamespaceMissing_Invalid),
                });

                // Uncomment tests below - when AES-GCM is released and supported
                /*
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, wrongSessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenEncryptionFailedException), "IDX10618"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid) + "_wrong_decrypting_session_key",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_192_Invalid,
                    ExpectedException = new ExpectedException(typeof(ArgumentOutOfRangeException), "IDX10653"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_192_Invalid) + "_wrong_decrypting_session_key",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_EncryptionAlgorithmNotSupported_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13623"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_EncryptionAlgorithmNotSupported_Invalid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_EncryptionAlgorithmNotSupported_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13623"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_EncryptionAlgorithmNotSupported_Invalid),
                });
                */

                // Throws as unsupported AES-GCM is used - remove when AES-GCM is released and supported
                var encryptingCredentials_PreSharedSessionKey_AESGCM = new EncryptingCredentials(sessionKey, SecurityAlgorithms.Aes128Gcm);
                var validationParams = CreateTokenValidationParameters(signingKey, sessionKey);
                validationParams.CryptoProviderFactory = null;
                tokenDescriptor_PreSharedSessionKey_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_PreSharedSessionKey_AESGCM);
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13623"),
                    ValidationParameters = validationParams,
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    TestId = "EncryptedAssertion_PreSharedSessionKey_AESGCM",
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(WriteEncryptedTokenTheoryData))]
        public void WriteEncryptedToken(Saml2TheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteEncryptedToken", theoryData);

            try
            {
                var token = theoryData.Handler.WriteToken(theoryData.SecurityToken);
                var saml2Token = theoryData.Handler.ReadSaml2Token(token);
                IdentityComparer.AreEqual(saml2Token.Assertion.Encrypted, true, context); // token should be encrypted

                if (string.IsNullOrEmpty(saml2Token.Assertion.EncryptedAssertion)) // if token is encrypted, EncryptedAssertion string should not be empty
                    context.Diffs.Add("!Assertion.EncryptedAssertion string should not be empty if Saml2Assertion.Encrypted == True");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> WriteEncryptedTokenTheoryData
        {
            get
            {
                // list keys used
                var key = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256;
                var sessionKey = KeyingMaterial.DefaultSymmetricSecurityKey_128;
                var cert = KeyingMaterial.DefaultCert_2048;

                var signingCredentials_Valid = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

                // encrypting credentials (Pre_Shared for one scenario and KeyWrap for another one)
                var encryptingCredentials_PreSharedSessionKey_Valid = new EncryptingCredentials(sessionKey, SecurityAlgorithms.Aes128Gcm);
                var encryptingCredentials_X509_Valid = new X509EncryptingCredentials(cert);
                var encryptingCredentials_X509_AlgNotSupported = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128Gcm);
                var encryptingCredentials_X509_EncNotSupported = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, SecurityAlgorithms.Aes128CbcHmacSha256);
                var encryptingCredentials_PreSharedSessionKey_AlgNotNone = new EncryptingCredentials(sessionKey, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, SecurityAlgorithms.Aes128Gcm);

                //SET HELPER CRYPTO PROVIDER FACTORY - remove when AES-GCM is released and supported
                encryptingCredentials_PreSharedSessionKey_Valid.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_X509_Valid.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_X509_AlgNotSupported.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_X509_EncNotSupported.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_PreSharedSessionKey_AlgNotNone.CryptoProviderFactory = new AesGcmProviderFactory();

                // token descriptors (Pre_Shared for one scenario and KeyWrap for another one)
                var tokenDescriptor_PreSharedSessionKey_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_PreSharedSessionKey_Valid);
                var tokenDescriptor_KeyWrap_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_X509_Valid);
                var tokenDescriptor_KeyWrap_AlgotithmNotSupported = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_X509_AlgNotSupported);
                var tokenDescriptor_KeyWrap_EncNotSupported = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_X509_EncNotSupported);
                var tokenDescriptor_PreSharedSessionKey_AlgotithmNotNone = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_PreSharedSessionKey_AlgNotNone);

                var tokenHandler = new Saml2SecurityTokenHandler();
                var theoryData = new TheoryData<Saml2TheoryData>();

                theoryData.Add(new Saml2TheoryData
                {
                    First = true,
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "EncryptedAssertion_PreSharedSessionKey_Valid",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "EncryptedAssertion_KeyWrap_Valid",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_AlgotithmNotSupported) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionEncryptionException), "IDX13627"),
                    TestId = "EncryptedAssertion_KeyWrap_AlgNotSupported",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_EncNotSupported) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionEncryptionException), "IDX13625"),
                    TestId = "EncryptedAssertion_KeyWrap_EncNotSupported",
                });

                // when pre-shared session key is being used, Algorithm should be set to None
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_AlgotithmNotNone) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionEncryptionException), "IDX13626"),
                    TestId = "EncryptedAssertion_PreSharedSessionKey_AlgNotNone",
                });

                // Throws as unsupported AES-GCM is used - remove when AES-GCM is released and supported
                var encryptingCredentials_PreSharedSessionKey_AESGCM = new EncryptingCredentials(sessionKey, SecurityAlgorithms.Aes128Gcm);
                tokenDescriptor_PreSharedSessionKey_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_PreSharedSessionKey_AESGCM);
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionEncryptionException), "IDX13601"),
                    TestId = "EncryptedAssertion_PreSharedSessionKey_AESGCM",
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(RoundTripEncryptedTokenTheoryData))]
        public void RoundTripEncryptedToken(Saml2TheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteEncryptedToken", theoryData);
            context.PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
             {
                 { typeof(Saml2Assertion), new List<string> { "IssueInstant", "Signature", "SigningCredentials", "EncryptingCredentials" } },
                 { typeof(Saml2SecurityToken), new List<string> { "SigningKey" } },
             };

            try
            {
                var token = theoryData.Handler.WriteToken(theoryData.SecurityToken);
                var saml2Token = theoryData.Handler.ReadSaml2Token(token);

                IdentityComparer.AreEqual(saml2Token.Assertion.Encrypted, true); // token should be encrypted
                if (string.IsNullOrEmpty(saml2Token.Assertion.EncryptedAssertion)) // if token is encrypted, EncryptedAssertion string should not be empty
                    context.Diffs.Add("!Assertion.EncryptedAssertion string should not be empty if Saml2Assertion.Encrypted == True");

                theoryData.Handler.ValidateToken(token, theoryData.ValidationParameters, out SecurityToken validatedToken); // validate/decrypt token
                IdentityComparer.AreEqual(validatedToken, theoryData.SecurityToken, context); // validated/decrypted token should be equal to the same token which was not encrypted
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> RoundTripEncryptedTokenTheoryData
        {
            get
            {
                // list keys
                var signingKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256;
                var sessionKey128 = KeyingMaterial.DefaultSymmetricSecurityKey_128;
                var sessionKey192 = KeyingMaterial.DefaultSymmetricSecurityKey_192;
                var sessionKey256 = KeyingMaterial.DefaultSymmetricSecurityKey_256;
                var cert = KeyingMaterial.DefaultCert_2048;

                var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

                // encrypting credentials (Pre_Shared for one scenario and KeyWrap for another one)
                var encryptingCredentials128_PreShared = new EncryptingCredentials(sessionKey128, SecurityAlgorithms.Aes128Gcm);
                var encryptingCredentials192_PreShared = new EncryptingCredentials(sessionKey192, SecurityAlgorithms.Aes192Gcm);
                var encryptingCredentials256_PreShared = new EncryptingCredentials(sessionKey256, SecurityAlgorithms.Aes256Gcm);
                var encryptingCredentials_KeyWrap_128_RSAOAEP = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, SecurityAlgorithms.Aes128Gcm);
                var encryptingCredentials_KeyWrap_192_RSAOAEP = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, SecurityAlgorithms.Aes192Gcm);
                var encryptingCredentials_KeyWrap_256_RSAOAEP = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, SecurityAlgorithms.Aes256Gcm);
                var encryptingCredentials_KeyWrap_128_Wrong_RSAOAEP_Identifier = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOaepKeyWrap, SecurityAlgorithms.Aes128Gcm);
                var encryptingCredentials_KeyWrap_192_Wrong_RSAOAEP_Identifier = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOaepKeyWrap, SecurityAlgorithms.Aes192Gcm);
                var encryptingCredentials_KeyWrap_256_Wrong_RSAOAEP_Identifier = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOaepKeyWrap, SecurityAlgorithms.Aes256Gcm);

                //SET HELPER CRYPTO PROVIDER FACTORY - remove when AES-GCM is released and supported
                encryptingCredentials128_PreShared.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials192_PreShared.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials256_PreShared.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_KeyWrap_128_RSAOAEP.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_KeyWrap_192_RSAOAEP.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_KeyWrap_256_RSAOAEP.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_KeyWrap_128_Wrong_RSAOAEP_Identifier.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_KeyWrap_192_Wrong_RSAOAEP_Identifier.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_KeyWrap_256_Wrong_RSAOAEP_Identifier.CryptoProviderFactory = new AesGcmProviderFactory();

                // token descriptors (Pre_Shared for one scenario and KeyWrap for another one)
                var tokenDescriptor_128_PreShared = CreateTokenDescriptor(signingCredentials, encryptingCredentials128_PreShared);
                var tokenDescriptor_192_PreShared = CreateTokenDescriptor(signingCredentials, encryptingCredentials192_PreShared);
                var tokenDescriptor_256_PreShared = CreateTokenDescriptor(signingCredentials, encryptingCredentials256_PreShared);
                var tokenDescriptor_KeyWrap_128_RSAOAEP = CreateTokenDescriptor(signingCredentials, encryptingCredentials_KeyWrap_128_RSAOAEP);
                var tokenDescriptor_KeyWrap_192_RSAOAEP = CreateTokenDescriptor(signingCredentials, encryptingCredentials_KeyWrap_192_RSAOAEP);
                var tokenDescriptor_KeyWrap_256_RSAOAEP = CreateTokenDescriptor(signingCredentials, encryptingCredentials_KeyWrap_256_RSAOAEP);
                var tokenDescriptor_KeyWrap_128_Wrong_RSAOAEP_Identifier = CreateTokenDescriptor(signingCredentials, encryptingCredentials_KeyWrap_128_Wrong_RSAOAEP_Identifier);
                var tokenDescriptor_KeyWrap_192_Wrong_RSAOAEP_Identifier = CreateTokenDescriptor(signingCredentials, encryptingCredentials_KeyWrap_192_Wrong_RSAOAEP_Identifier);
                var tokenDescriptor_KeyWrap_256_Wrong_RSAOAEP_Identifier = CreateTokenDescriptor(signingCredentials, encryptingCredentials_KeyWrap_256_Wrong_RSAOAEP_Identifier);

                var tokenDescriptor_KeyWrap_Signed = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    NotBefore = Default.NotBefore,
                    Expires = Default.Expires,
                    Issuer = Default.Issuer,
                    EncryptingCredentials = new X509EncryptingCredentials(KeyingMaterial.DefaultCert_2048), // encrypt with 'one-time-use' session key and wrap a session key using public cert
                    SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest),
#pragma warning disable 0618
                    Subject = new ClaimsIdentity(Default.SamlClaims)
#pragma warning restore 0618
                };

                var tokenHandler = new Saml2SecurityTokenHandler();
                var theoryData = new TheoryData<Saml2TheoryData>();

                // test both scenarios and test all supported combinations (sessionKey-keywrapKey) in KeyWrap scenario
                theoryData.Add(new Saml2TheoryData
                {
                    First = true,
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_128_PreShared) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey128),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_128_PreShared),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_192_PreShared) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey192),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_192_PreShared),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_256_PreShared) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey256),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_256_PreShared),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_128_RSAOAEP) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_KeyWrap_128_RSAOAEP),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_192_RSAOAEP) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_KeyWrap_192_RSAOAEP),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_256_RSAOAEP) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_KeyWrap_256_RSAOAEP),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_128_Wrong_RSAOAEP_Identifier) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_KeyWrap_128_Wrong_RSAOAEP_Identifier),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_192_Wrong_RSAOAEP_Identifier) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_KeyWrap_192_Wrong_RSAOAEP_Identifier),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_256_Wrong_RSAOAEP_Identifier) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_KeyWrap_256_Wrong_RSAOAEP_Identifier),
                });

                return theoryData;
            }
        }

        // helper method to create a common SecurityTokenDescriptor
        private static SecurityTokenDescriptor CreateTokenDescriptor(SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials)
        {
            return new SecurityTokenDescriptor
            {
                Audience = Default.Audience,
                NotBefore = Default.NotBefore,
                Expires = Default.Expires,
                Issuer = Default.Issuer,
                SigningCredentials = signingCredentials,
                EncryptingCredentials = encryptingCredentials,
#pragma warning disable 0618
                Subject = new ClaimsIdentity(Default.SamlClaims),
#pragma warning restore 0618
            };
        }

        // helper method to create a common TokenValidationParameters
        private static TokenValidationParameters CreateTokenValidationParameters(SecurityKey signingKey, SecurityKey decryptionKey)
        {
            return new TokenValidationParameters
            {
                IssuerSigningKey = signingKey,
                TokenDecryptionKey = decryptionKey,
                ValidAudience = Default.Audience,
                ValidIssuer = Default.Issuer,
                ValidateLifetime = false,
                ValidateTokenReplay = false,
                ValidateActor = false,
                CryptoProviderFactory = new AesGcmProviderFactory(), // //SET HELPER CRYPTO PROVIDER FACTORY - remove when AES-GCM is released and supported
            };
        }

        #endregion
#endif
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
