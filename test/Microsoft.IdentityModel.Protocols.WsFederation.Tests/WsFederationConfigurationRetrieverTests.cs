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

namespace Microsoft.IdentityModel.Protocols.WsFederation.Tests
{
    /// <summary>
    /// Ws-Fed metadata reading tests.
    /// </summary>
    public class WsFederationConfigurationRetrieverTests
    {
        private static bool _firstTest = true;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("MetadataTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadMetadataTest(WsFederationMetadataTheoryData theoryData)
        {
            TestUtilities.TestHeader($"{this}.ReadMetadataTest", theoryData.TestId, ref _firstTest);
            try
            {
                XmlReader reader = XmlReader.Create(new StringReader(theoryData.Metadata));
                WsFederationMetadataSerializer serializer = new WsFederationMetadataSerializer();
                WsFederationConfiguration configuration = serializer.ReadMetadata(reader);

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
                var theoryData = new TheoryData<WsFederationMetadataTheoryData>();

                theoryData.Add(
                    new WsFederationMetadataTheoryData
                    {
                        Metadata = ReferenceMetadata.Metadata,
                        Issuer = "https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/",
                        TokenEndpoint = "https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed",
                        KeyInfoCount = 3,
                        TestId = nameof(ReferenceMetadata.Metadata)
                    });

                theoryData.Add(
                    new WsFederationMetadataTheoryData
                    {
                        Metadata = ReferenceMetadata.MetadataNoIssuer,
                        TestId = nameof(ReferenceMetadata.MetadataNoIssuer),
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13001")
                    });

                theoryData.Add(
                    new WsFederationMetadataTheoryData
                    {
                        Metadata = ReferenceMetadata.MetadataNoTokenUri,
                        TestId = nameof(ReferenceMetadata.MetadataNoTokenUri),
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13003")
                    });

                return theoryData;
            }
        }

        public class WsFederationMetadataTheoryData
        {
            public string Metadata { get; set; }

            public string Issuer { get; set; }

            public string TokenEndpoint { get; set; }

            public int KeyInfoCount { get; set; }

            public string TestId { get; set; }

            public ExpectedException ExpectedException { get; set; } = ExpectedException.NoExceptionExpected;
        }
    }
}
