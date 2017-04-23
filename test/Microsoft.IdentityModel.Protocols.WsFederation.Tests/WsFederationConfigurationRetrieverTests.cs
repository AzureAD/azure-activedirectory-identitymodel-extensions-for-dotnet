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
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using Xunit;

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
            TestUtilities.WriteHeader($"{this}.ReadMetadataTest", theoryData);
            List<string> errors = new List<string>();

            try
            {
                XmlReader reader = XmlReader.Create(new StringReader(theoryData.Metadata));
                var serializer = new WsFederationMetadataSerializer();
                var configuration = serializer.ReadMetadata(reader);

                if (theoryData.SigingKey != null)
                    configuration.Signature.Verify(theoryData.SigingKey);

                theoryData.ExpectedException.ProcessNoException();

                Comparer.GetDiffs(theoryData.Configuration, configuration, errors);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(errors);
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
#if !NETCOREAPP1_0
                        ExpectedException = ExpectedException.NoExceptionExpected,
#else
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13000:", typeof(NotSupportedException)),
#endif
                        First = true,
                        Configuration = ReferenceMetadata.GoodConfigurationCommonEndpoint,
                        Metadata = ReferenceMetadata.AADCommonMetadata,
                        SigingKey = ReferenceMetadata.AADCommonMetadataSigningKey,
                        TestId = nameof(ReferenceMetadata.AADCommonMetadata)
                    });

                theoryData.Add(
                    new WsFederationMetadataTheoryData
                    {
#if !NETCOREAPP1_0
                        ExpectedException = ExpectedException.NoExceptionExpected,
#else
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13000:", typeof(NotSupportedException)),
#endif
                        Configuration = ReferenceMetadata.GoodConfiguration,
                        Metadata = ReferenceMetadata.Metadata,
                        TestId = nameof(ReferenceMetadata.Metadata)
                    });

                theoryData.Add(
                    new WsFederationMetadataTheoryData
                    {
#if !NETCOREAPP1_0
                        ExpectedException = new ExpectedException(typeof(CryptographicException), "IDX21200:"),
#else
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13000:", typeof(NotSupportedException)),
#endif
                        Configuration = ReferenceMetadata.GoodConfiguration,
                        Metadata = ReferenceMetadata.Metadata,
                        SigingKey = ReferenceMetadata.AADCommonMetadataSigningKey,
                        TestId = nameof(ReferenceMetadata.Metadata) + " Signature Failure"
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
#if !NETCOREAPP1_0
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13003:"),
#else
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13000:", typeof(NotSupportedException)),
#endif
                        Metadata = ReferenceMetadata.MetadataNoTokenUri,
                        TestId = nameof(ReferenceMetadata.MetadataNoTokenUri)
                    });

                theoryData.Add(
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21017:", typeof(FormatException)),
                        Metadata = ReferenceMetadata.MetadataMalformedCertificate,
                        TestId = nameof(ReferenceMetadata.MetadataMalformedCertificate)
                    });

                return theoryData;
            }
        }

        public class WsFederationMetadataTheoryData : TheoryDataBase
        {
            public string Metadata { get; set; }

            public SecurityKey SigingKey { get; set; }

            public WsFederationConfiguration Configuration { get; set; }

            public override string ToString()
            {
                return $"TestId: {TestId}, {ExpectedException}";
            }
        }
    }
}
