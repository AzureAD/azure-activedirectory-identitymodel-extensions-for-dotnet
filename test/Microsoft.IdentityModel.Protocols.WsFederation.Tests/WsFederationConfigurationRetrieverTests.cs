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

using Microsoft.IdentityModel.Tokens.Tests;
using Microsoft.IdentityModel.Xml;
using System;
using System.IO;
using System.Xml;
using Xunit;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Microsoft.IdentityModel.Protocols.WsFederation.Tests
{
    /// <summary>
    /// Ws-Fed metadata reading tests.
    /// </summary>
    public class WsFederationConfigurationRetrieverTests
    {

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("MetadataTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadMetadataTest(WsFederationMetadataTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadMetadataTest", theoryData.TestId, theoryData.First);
            try
            {
                XmlReader reader = XmlReader.Create(new StringReader(theoryData.Metadata));
                var serializer = new WsFederationMetadataSerializer();
                var configuration = serializer.ReadMetadata(reader);
                if (theoryData.SigingKey != null)
                    configuration.Signature.Verify(theoryData.SigingKey);

                Assert.Equal(theoryData.Issuer, configuration.Issuer);
                Assert.Equal(theoryData.TokenEndpoint, configuration.TokenEndpoint);
                Assert.Equal(theoryData.KeyInfoCount, configuration.KeyInfos.Count);

                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<WsFederationMetadataTheoryData> MetadataTheoryData
        {
            get
            {
                // uncomment to see exception displayed to user.
                // ExpectedException.DefaultVerbose = true;

                var theoryData = new TheoryData<WsFederationMetadataTheoryData>();

                theoryData.Add(
                    new WsFederationMetadataTheoryData
                    {
                        First = true,
                        Issuer = "https://sts.windows.net/{tenantid}/",
                        KeyInfoCount = 3,
                        Metadata = ReferenceMetadata.AADCommonMetadata,
                        SigingKey = ReferenceMetadata.AADCommonMetadataSigningKey,
                        TestId = nameof(ReferenceMetadata.AADCommonMetadata),
                        TokenEndpoint = "https://login.microsoftonline.com/common/wsfed"
                    });

                theoryData.Add(
                    new WsFederationMetadataTheoryData
                    {
                        Issuer = "https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/",
                        KeyInfoCount = 3,
                        Metadata = ReferenceMetadata.Metadata,
                        TestId = nameof(ReferenceMetadata.Metadata),
                        TokenEndpoint = "https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed",
                    });

                theoryData.Add(
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(CryptographicException), "IDX21200:"),
                        Issuer = "https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/",
                        KeyInfoCount = 3,
                        Metadata = ReferenceMetadata.Metadata,
                        SigingKey = ReferenceMetadata.AADCommonMetadataSigningKey,
                        TestId = nameof(ReferenceMetadata.Metadata) + " Signature Failure",
                        TokenEndpoint = "https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed",
                    });

                theoryData.Add(
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13001:"),
                        Metadata = ReferenceMetadata.MetadataNoIssuer,
                        TestId = nameof(ReferenceMetadata.MetadataNoIssuer)
                    });

                theoryData.Add(
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13003:"),
                        Metadata = ReferenceMetadata.MetadataNoTokenUri,
                        TestId = nameof(ReferenceMetadata.MetadataNoTokenUri)
                    });

                return theoryData;
            }
        }

        public class WsFederationMetadataTheoryData : TheoryDataBase
        {
            public string Issuer { get; set; }

            public int KeyInfoCount { get; set; }

            public string Metadata { get; set; }

            public SecurityKey SigingKey { get; set; }

            public string TokenEndpoint { get; set; }

            public override string ToString()
            {
                return $"TestId: {TestId}, {ExpectedException}, Metadata: {Metadata}.";
            }
        }
    }
}
