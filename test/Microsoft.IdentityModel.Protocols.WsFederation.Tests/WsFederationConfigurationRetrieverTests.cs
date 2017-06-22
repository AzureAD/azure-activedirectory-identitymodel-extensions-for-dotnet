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
            var errors = new List<string>();

            try
            {
                var reader = XmlReader.Create(new StringReader(theoryData.Metadata));
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadEntityDescriptorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadEntityDescriptorTest(WsFederationMetadataTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadEntityDescriptorTest", theoryData);
            var serializer = new WsFederationMetadataSerializerPublic();
            try
            {
                serializer.ReadEntityDescriptorPublic(null, XmlReader.Create(new StringReader("some string")));
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            try
            {
                serializer.ReadEntityDescriptorPublic(new WsFederationConfiguration(), null);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadKeyDescriptorForSigningTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadKeyDescriptorForSigningTest(WsFederationMetadataTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadKeyDescriptorForSigningTheoryData", theoryData);
            var serializer = new WsFederationMetadataSerializerPublic();
            try
            {
                serializer.ReadKeyDescriptorForSigningPublic(null, XmlReader.Create(new StringReader("some string")));
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            try
            {
                serializer.ReadKeyDescriptorForSigningPublic(new WsFederationConfiguration(), null);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadKeyDescriptorForSigningKeyUseTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadKeyDescriptorForSigningKeyUseTest(WsFederationMetadataTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadKeyDescriptorForSigningTheoryData", theoryData);
            var serializer = new WsFederationMetadataSerializerPublic();
            try
            {
                serializer.ReadKeyDescriptorForSigningPublic(new WsFederationConfiguration(), XmlReader.Create(new StringReader(theoryData.Metadata)));
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadSecurityTokenServiceTypeRoleDescriptorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadSecurityTokenServiceTypeRoleDescriptorTest(WsFederationMetadataTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadSecurityTokenServiceTypeRoleDescriptorTest", theoryData);
            var serializer = new WsFederationMetadataSerializerPublic();
            try
            { 
                serializer.ReadSecurityTokenServiceTypeRoleDescriptorPublic(null, XmlReader.Create(new StringReader("some string")));
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            try
            {
                serializer.ReadSecurityTokenServiceTypeRoleDescriptorPublic(new WsFederationConfiguration(), null);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadSecurityTokenEndpointTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadSecurityTokenEndpointTest(WsFederationMetadataTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadSecurityTokenEndpointTest", theoryData);
            var serializer = new WsFederationMetadataSerializerPublic();
            try
            {
                serializer.ReadSecurityTokenEndpointPublic(null, XmlReader.Create(new StringReader("some string")));
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            try
            { 
                serializer.ReadSecurityTokenEndpointPublic(new WsFederationConfiguration(), null);
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

                return new TheoryData<WsFederationMetadataTheoryData>
                {
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        First = true,
                        Configuration = ReferenceMetadata.GoodConfigurationCommonEndpoint,
                        Metadata = ReferenceMetadata.AADCommonMetadata,
                        SigingKey = ReferenceMetadata.AADCommonMetadataSigningKey,
                        TestId = nameof(ReferenceMetadata.AADCommonMetadata)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Configuration = ReferenceMetadata.GoodConfiguration,
                        Metadata = ReferenceMetadata.Metadata,
                        TestId = nameof(ReferenceMetadata.Metadata)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(CryptographicException), "IDX21200:"),
                        Configuration = ReferenceMetadata.GoodConfiguration,
                        Metadata = ReferenceMetadata.Metadata,
                        SigingKey = ReferenceMetadata.AADCommonMetadataSigningKey,
                        TestId = nameof(ReferenceMetadata.Metadata) + " Signature Failure"
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Configuration = ReferenceMetadata.GoodConfiguration,
                        Metadata = ReferenceMetadata.MetadataWithBlanks,
                        TestId = nameof(ReferenceMetadata.MetadataWithBlanks)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Configuration = new WsFederationConfiguration
                        {
                            Issuer = ReferenceMetadata.Issuer,
                            TokenEndpoint = ReferenceMetadata.TokenEndpoint
                        },
                        Metadata = ReferenceMetadata.MetadataNoKeyDescriptorForSigningInRoleDescriptor,
                        TestId = nameof(ReferenceMetadata.MetadataNoKeyDescriptorForSigningInRoleDescriptor)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13001:"),
                        Metadata = ReferenceMetadata.MetadataNoIssuer,
                        TestId = nameof(ReferenceMetadata.MetadataNoIssuer)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13003:"),
                        Metadata = ReferenceMetadata.MetadataNoTokenUri,
                        TestId = nameof(ReferenceMetadata.MetadataNoTokenUri)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21017:", typeof(FormatException)),
                        Metadata = ReferenceMetadata.MetadataMalformedCertificate,
                        TestId = nameof(ReferenceMetadata.MetadataMalformedCertificate)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                        Metadata = ReferenceMetadata.MetadataNoKeyInfoInSignature,
                        TestId = nameof(ReferenceMetadata.MetadataNoKeyInfoInSignature)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                        Metadata = ReferenceMetadata.MetadataNoSignedInfoInSignature,
                        TestId = nameof(ReferenceMetadata.MetadataNoSignedInfoInSignature)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                        Metadata = ReferenceMetadata.MetadataNoEntityDescriptor,
                        TestId = nameof(ReferenceMetadata.MetadataNoEntityDescriptor)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13004:"),
                        Metadata = ReferenceMetadata.MetadataNoRoleDescriptor,
                        TestId = nameof(ReferenceMetadata.MetadataNoRoleDescriptor)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13002:"),
                        Metadata = ReferenceMetadata.MetadataNoKeyInfoInKeyDescriptor,
                        TestId = nameof(ReferenceMetadata.MetadataNoKeyInfoInKeyDescriptor)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Configuration = new WsFederationConfiguration
                        {
                            Issuer = ReferenceMetadata.Issuer
                        },
                        Metadata = ReferenceMetadata.MetadataNoSecurityTokenSeviceEndpointInRoleDescriptor,
                        TestId = nameof(ReferenceMetadata.MetadataNoSecurityTokenSeviceEndpointInRoleDescriptor)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                        Metadata = ReferenceMetadata.MetadataNoEndpointReference,
                        TestId = nameof(ReferenceMetadata.MetadataNoEndpointReference)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                        Metadata = ReferenceMetadata.MetadataNoAddressInEndpointReference,
                        TestId = nameof(ReferenceMetadata.MetadataNoAddressInEndpointReference)
                    }
                };
            }
        }

        public static TheoryData<WsFederationMetadataTheoryData> ReadEntityDescriptorTheoryData
        {
            get
            {
                return new TheoryData<WsFederationMetadataTheoryData>
                {
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        TestId = "ReadEntityDescriptor"
                    }
                };
            }
        }

        public static TheoryData<WsFederationMetadataTheoryData> ReadKeyDescriptorForSigningTheoryData
        {
            get
            {
                return new TheoryData<WsFederationMetadataTheoryData>
                {
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        TestId = "ReadKeyDescriptorForSigning"
                    }
                };
            }
        }

        public static TheoryData<WsFederationMetadataTheoryData> ReadKeyDescriptorForSigningKeyUseTheoryData
        {
            get
            {
                return new TheoryData<WsFederationMetadataTheoryData>
                {
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Metadata = ReferenceMetadata.KeyDescriptorNoKeyUse,
                        TestId = "ReadKeyDescriptorForSigning: 'use' is null"
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX13009:"),
                        Metadata = ReferenceMetadata.KeyDescriptorKeyUseNotForSigning,
                        TestId = "ReadKeyDescriptorForSigning: 'use' is not 'signing'"
                    }
                };
            }
        }

        public static TheoryData<WsFederationMetadataTheoryData> ReadSecurityTokenServiceTypeRoleDescriptorTheoryData
        {
            get
            {
                return new TheoryData<WsFederationMetadataTheoryData>
                {
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        TestId = "ReadSecurityTokenServiceTypeRoleDescriptor"
                    }
                };
            }
        }

        public static TheoryData<WsFederationMetadataTheoryData> ReadSecurityTokenEndpointTheoryData
        {
            get
            {
                return new TheoryData<WsFederationMetadataTheoryData>
                {
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        TestId = "ReadSecurityTokenEndpoint"
                    }
                };
            }
        }

        public class WsFederationMetadataTheoryData : TheoryDataBase
        {
            public WsFederationConfiguration Configuration { get; set; }

            public string Metadata { get; set; }

            public SecurityKey SigingKey { get; set; }

            public override string ToString()
            {
                return $"TestId: {TestId}, {ExpectedException}";
            }
        }

        private class WsFederationMetadataSerializerPublic : WsFederationMetadataSerializer
        {
            public void ReadEntityDescriptorPublic(WsFederationConfiguration configuration, XmlReader reader)
            {
                base.ReadEntityDescriptor(configuration, reader);
            }

            public void ReadKeyDescriptorForSigningPublic(WsFederationConfiguration configuration, XmlReader reader)
            {
                base.ReadKeyDescriptorForSigning(configuration, reader);
            }

            public void ReadSecurityTokenServiceTypeRoleDescriptorPublic(WsFederationConfiguration configuration, XmlReader reader)
            {
                base.ReadSecurityTokenServiceTypeRoleDescriptor(configuration, reader);
            }

            public void ReadSecurityTokenEndpointPublic(WsFederationConfiguration configuration, XmlReader reader)
            {
                base.ReadSecurityTokenEndpoint(configuration, reader);
            }
        }
    }
}
