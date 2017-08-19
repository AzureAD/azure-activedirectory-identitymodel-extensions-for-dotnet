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
using System.IO;
using System.Xml;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.WsFederation.Tests
{
    /// <summary>
    /// WsFed metadata reading tests.
    /// </summary>
    public class WsFederationConfigurationRetrieverTests
    {

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadMetadataTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadMetadata(WsFederationMetadataTheoryData theoryData)
        {
            var context  = TestUtilities.WriteHeader($"{this}.ReadMetadata", theoryData);
            try
            {
                var reader = XmlReader.Create(new StringReader(theoryData.Metadata));
                var configuration = theoryData.Serializer.ReadMetadata(reader);

                if (theoryData.SigingKey != null)
                    configuration.Signature.Verify(theoryData.SigingKey);

                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreWsFederationConfigurationsEqual(configuration, theoryData.Configuration, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsFederationMetadataTheoryData> ReadMetadataTheoryData
        {
            get
            {
                // uncomment to see exception displayed to user.
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<WsFederationMetadataTheoryData>
                {
                    new WsFederationMetadataTheoryData
                    {
                        Configuration = ReferenceMetadata.AADCommonEndpoint,
                        First = true,
                        Metadata = ReferenceMetadata.AADCommonMetadata,
                        SigingKey = ReferenceMetadata.MetadataSigningKey,
                        TestId = nameof(ReferenceMetadata.AADCommonMetadata)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        Configuration = ReferenceMetadata.AADCommonFormated,
                        Metadata = ReferenceMetadata.AADCommonMetadataFormated,
                        TestId = nameof(ReferenceMetadata.AADCommonMetadataFormated)
                    },
                    new WsFederationMetadataTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlValidationException), "IDX21200:"),
                        Configuration = ReferenceMetadata.AADCommonFormated,
                        Metadata = ReferenceMetadata.AADCommonMetadataFormated,
                        SigingKey = ReferenceMetadata.MetadataSigningKey,
                        TestId = nameof(ReferenceMetadata.AADCommonMetadataFormated) + " Signature Failure"
                    },
                    new WsFederationMetadataTheoryData
                    {
                        Configuration = ReferenceMetadata.AADCommonFormated,
                        Metadata = ReferenceMetadata.MetadataWithBlanks,
                        TestId = nameof(ReferenceMetadata.MetadataWithBlanks)
                    },
                    new WsFederationMetadataTheoryData
                    {
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
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21025:"),
                        Metadata = ReferenceMetadata.MetadataUnknownElementBeforeSignatureEndElement,
                        TestId = nameof(ReferenceMetadata.MetadataUnknownElementBeforeSignatureEndElement)
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadEntityDescriptorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadEntityDescriptor(WsFederationMetadataTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadEntityDescriptor", theoryData);
            var serializer = new WsFederationMetadataSerializerPublic();
            try
            {
                serializer.ReadEntityDescriptorPublic(null);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
            TestUtilities.AssertFailIfErrors(context);
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadKeyDescriptorForSigningTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadKeyDescriptorForSigning(WsFederationMetadataTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadKeyDescriptorForSigning", theoryData);
            var serializer = new WsFederationMetadataSerializerPublic();
            try
            {
                serializer.ReadKeyDescriptorForSigningPublic(null);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
            TestUtilities.AssertFailIfErrors(context);
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadKeyDescriptorForSigningKeyUseTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadKeyDescriptorForSigningKeyUse(WsFederationMetadataTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadKeyDescriptorForSigningKeyUse", theoryData);
            var serializer = new WsFederationMetadataSerializerPublic();
            try
            {
                serializer.ReadKeyDescriptorForSigningPublic(XmlReader.Create(new StringReader(theoryData.Metadata)));
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
            TestUtilities.AssertFailIfErrors(context);
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadSecurityTokenServiceTypeRoleDescriptorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadSecurityTokenServiceTypeRoleDescriptor(WsFederationMetadataTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadSecurityTokenServiceTypeRoleDescriptor", theoryData);
            var serializer = new WsFederationMetadataSerializerPublic();
            try
            {
                serializer.ReadSecurityTokenServiceTypeRoleDescriptorPublic(null);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
            TestUtilities.AssertFailIfErrors(context);
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadSecurityTokenEndpointTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadSecurityTokenEndpoint(WsFederationMetadataTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadSecurityTokenEndpoint", theoryData);
            var serializer = new WsFederationMetadataSerializerPublic();
            try
            { 
                serializer.ReadSecurityTokenEndpointPublic(null);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
            TestUtilities.AssertFailIfErrors(context);
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

            public WsFederationMetadataSerializer Serializer { get; set; } = new WsFederationMetadataSerializer();

            public SecurityKey SigingKey { get; set; }

            public override string ToString()
            {
                return $"TestId: {TestId}, {ExpectedException}";
            }
        }

        private class WsFederationMetadataSerializerPublic : WsFederationMetadataSerializer
        {
            public WsFederationConfiguration ReadEntityDescriptorPublic(XmlReader reader)
            {
                return base.ReadEntityDescriptor(reader);
            }

            public KeyInfo ReadKeyDescriptorForSigningPublic(XmlReader reader)
            {
                return base.ReadKeyDescriptorForSigning(reader);
            }

            public SecurityTokenServiceTypeRoleDescriptor ReadSecurityTokenServiceTypeRoleDescriptorPublic(XmlReader reader)
            {
                return base.ReadSecurityTokenServiceTypeRoleDescriptor(reader);
            }

            public string ReadSecurityTokenEndpointPublic(XmlReader reader)
            {
                return base.ReadSecurityTokenEndpoint(reader);
            }
        }
    }
}
