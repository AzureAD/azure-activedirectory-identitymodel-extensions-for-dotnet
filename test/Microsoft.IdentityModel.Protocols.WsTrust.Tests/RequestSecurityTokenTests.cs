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
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class RequestSecurityTokenTests
    {
        [Theory, MemberData(nameof(ReadAndWriteRequestTheoryData))]
        public void ReadAndWriteRequest(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadAndWriteRequest", theoryData);
            try
            {
                var memeoryStream = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(memeoryStream, Encoding.UTF8);
                var serializer = new WsTrustSerializer();
                serializer.WriteRequest(writer, theoryData.WsTrustVersion, theoryData.WsTrustRequest);
                writer.Flush();
                var bytes = memeoryStream.ToArray();
                var xml = Encoding.UTF8.GetString(bytes);
                var reader = XmlDictionaryReader.CreateTextReader(bytes, XmlDictionaryReaderQuotas.Max);
                var trustRequest = serializer.ReadRequest(reader);
                IdentityComparer.AreEqual(trustRequest, theoryData.WsTrustRequest, context);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadAndWriteRequestTheoryData
        {
            get
            {
                var additionalContext = new AdditionalContext(
                    new List<ContextItem>
                    {
                        new ContextItem
                        {
                            Name = "http://schemas.microsoft.com/wlid/requestor",
                            Scope = "http://schemas.xmlsoap.org/ws/2006/12/authorization/ctx/requestor",
                            Value = "outlook.com"
                        }
                    });

                var claimTypes = new List<ClaimType> {
                    new ClaimType {
                        Uri = "http://schemas.xmlsoap.org/ws/2006/12/authorization/claims/action",
                        IsOptional = true,
                        Value = "MSExchange.SharingCalendarFreeBusy"
                    }
                };

                var claims = new Claims("http://schemas.xmlsoap.org/ws/2006/12/authorization/authclaims", claimTypes);
                var tokenDescriptor = Default.SecurityTokenDescriptor(Default.AsymmetricSigningCredentials);
                var saml2TokenHandler = new Saml2SecurityTokenHandler();
                var saml2Token = saml2TokenHandler.CreateToken(tokenDescriptor);
                var token = saml2TokenHandler.WriteToken(saml2Token);
                saml2TokenHandler.ValidateToken(
                    token, 
                    new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        IssuerSigningKey = Default.AsymmetricSigningCredentials.Key
                    },
                    out SecurityToken saml2SecurityToken);

                var trustConstants = WsTrust13Constants.Instance;
                var propertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>> { { typeof(Saml2SecurityToken), new List<string> { "SigningKey" } } };

                var doc = new XmlDocument();
                doc.LoadXml("<UnknownElement attribute1=\"1\">this is an unknownElement</UnknownElement>");
                var xmlElement = doc.DocumentElement;
                var wsTrustRequest = new WsTrustRequest(trustConstants.WsTrustActions.Issue)
                {
                    AdditionalContext = additionalContext,
                    AppliesTo = WsDefaults.AppliesTo,
                    CanonicalizationAlgorithm = SecurityAlgorithms.ExclusiveC14n,
                    Claims = claims,
                    Context = Guid.NewGuid().ToString(),
                    ComputedKeyAlgorithm = trustConstants.WsTrustKeyTypes.PSHA1,
                    EncryptionAlgorithm = SecurityAlgorithms.Aes256Encryption,
                    EncryptWith = SecurityAlgorithms.Aes256Encryption,
                    KeySizeInBits = 256,
                    KeyType = trustConstants.WsTrustKeyTypes.Symmetric,
                    OnBehalfOf = new SecurityTokenElement(saml2SecurityToken),
                    PolicyReference = new PolicyReference
                    {
                        Uri = "MSExchange.SharingCalendarFreeBusy",
                        DigestAlgorithm = SecurityAlgorithms.Sha256Digest,
                        Digest = Guid.NewGuid().ToString()
                    },
                    SignWith = SecurityAlgorithms.Aes128CbcHmacSha256,
                    TokenType = Saml2Constants.OasisWssSaml2TokenProfile11,
                    UseKey = new UseKey(new SecurityTokenElement(WsDefaults.SecurityTokenReference)) { SignatureId = Guid.NewGuid().ToString() },

                    // TODO Enable this once SecurityKeys are serialized and deserialized
                    // ProofEncryptionKey = Default.AsymmetricEncryptionKeyPublic,
                };

                wsTrustRequest.AdditionalXmlElements.Add(xmlElement);

                return new TheoryData<WsTrustTheoryData>
                {
                    //<t:RequestSecurityToken Id="uuid-bdda680b-0921-4060-ac39-3429dc8ce7b5">
                    //    <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
                    //    <t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1</t:TokenType>
                    //    <t:KeyType>http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey</t:KeyType>
                    //    <t:KeySize>256</t:KeySize>
                    //    <t:CanonicalizationAlgorithm>http://www.w3.org/2001/10/xml-exc-c14n#</t:CanonicalizationAlgorithm>
                    //    <t:EncryptionAlgorithm>http://www.w3.org/2001/04/xmlenc#aes256-cbc</t:EncryptionAlgorithm>
                    //    <t:EncryptWith>http://www.w3.org/2001/04/xmlenc#aes256-cbc</t:EncryptWith>
                    //    <t:SignWith>http://www.w3.org/2000/09/xmldsig#hmac-sha1</t:SignWith>
                    //    <t:ComputedKeyAlgorithm>http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1</t:ComputedKeyAlgorithm>
                    //    <wsp:AppliesTo>
                    //        <a:EndpointReference>
                    //            <a:Address>http://exchangecalendarsharing.com</a:Address>
                    //        </a:EndpointReference>
                    //    </wsp:AppliesTo>
                    //    <t:OnBehalfOf>
                    //        <saml:Assertion MajorVersion="1" MinorVersion="1" AssertionID="saml-9e1c03a5-7bfe-4945-838b-f784e285cdb9" Issuer="outlook.com" IssueInstant="2010-09-14T23:28:00.499Z" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion">
                    //        </saml:Assertion>
                    //    </t:OnBehalfOf>
                    //    <auth:AdditionalContext>
                    //        <auth:ContextItem Scope="http://schemas.xmlsoap.org/ws/2006/12/authorization/ctx/requestor" Name="http://schemas.microsoft.com/wlid/requestor">
                    //            <auth:Value>outlook.com</auth:Value>
                    //        </auth:ContextItem>
                    //    </auth:AdditionalContext>
                    //    <t:Claims Dialect="http://schemas.xmlsoap.org/ws/2006/12/authorization/authclaims">
                    //        <auth:ClaimType Uri="http://schemas.xmlsoap.org/ws/2006/12/authorization/claims/action">
                    //            <auth:Value>MSExchange.SharingCalendarFreeBusy</auth:Value>
                    //        </auth:ClaimType>
                    //    </t:Claims>
                    //    <wsp:PolicyReference URI="EX_MBI_FED_SSL"></wsp:PolicyReference>
                    //</t:RequestSecurityToken>


                    new WsTrustTheoryData
                    {
                        First = true,
                        PropertiesToIgnoreWhenComparing = propertiesToIgnoreWhenComparing,
                        WsTrustRequest = wsTrustRequest,
                        TestId = "WsTrustRequestWithSaml2OBO",
                        WsTrustVersion = WsTrustVersion.Trust13
                    }
                };
            }
        }

        [Theory, MemberData(nameof(ReadRequestTheoryData))]
        public void ReadRequest(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadRequest", theoryData);

            try
            {
                var request = theoryData.WsTrustSerializer.ReadRequest(theoryData.Reader);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(request, theoryData.WsTrustRequest, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadRequestTheoryData
        {
            get
            {
                var theoryData = new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("reader"),
                        First = true,
                        TestId = "ReaderNull",
                    }
                };

                XmlDictionaryReader reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust13, DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromDays(1));
                reader.ReadStartElement();
                reader.ReadStartElement();
                theoryData.Add(new WsTrustTheoryData(WsTrustVersion.Trust13)
                {
                    ExpectedException = ExpectedException.XmlReadException("IDX30022:"),
                    Reader = reader,
                    TestId = "ReaderNotOnStartElement"
                });

                theoryData.Add(new WsTrustTheoryData(WsTrustVersion.Trust13)
                {
                    ExpectedException = ExpectedException.XmlReadException("IDX30024:"),
                    Reader = ReferenceXml.RandomElementReader,
                    TestId = "ReaderNotOnCorrectElement"
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(WriteRequestTheoryData))]
        public void WriteRequest(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteRequest", theoryData);
            try
            {
                theoryData.WsTrustSerializer.WriteRequest(theoryData.Writer, theoryData.WsTrustVersion, theoryData.WsTrustRequest);
                //IdentityComparer.AreEqual(lifetime, theoryData.Lifetime, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteRequestTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("wsTrustVersion"),
                        First = true,
                        TestId = "WsTrustVersionNull",
                        WsTrustRequest = new WsTrustRequest(WsTrustConstants.Trust13.WsTrustActions.Issue),
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        TestId = "WriterNull",
                        WsTrustRequest = new WsTrustRequest(WsTrustConstants.Trust13.WsTrustActions.Issue),
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("trustRequest"),
                        TestId = "WsTrustRequestNull"
                    }
                };
            }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
