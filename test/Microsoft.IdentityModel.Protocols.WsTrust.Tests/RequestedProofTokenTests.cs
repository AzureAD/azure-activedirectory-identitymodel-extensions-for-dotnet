using System;
using System.IO;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class RequestedProofTokenTests
    {
        [Theory, MemberData(nameof(ReadRequestedProofTokenTestCases))]
        public void ReadRequestedProofToken(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadRequestedProofToken", theoryData);

            try
            {
                var requestedProofToken = WsTrustSerializer.ReadRequestedProofToken(theoryData.Reader, theoryData.WsSerializationContext);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(requestedProofToken, theoryData.RequestedProofToken, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadRequestedProofTokenTestCases
        {
            get
            {
                var theoryData = new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(WsTrustReferenceXml.RandomElementReader)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        Reader = WsTrustReferenceXml.GetRequestSecurityTokenReader(WsTrustConstants.Trust13, ReferenceXml.Saml2Valid),
                        TestId = "SerializationContextNull",
                        WsSerializationContext = null
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("reader"),
                        Reader = null,
                        TestId = "ReaderNull",
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.XmlReadException(),
                        Reader = WsTrustReferenceXml.RandomElementReader,
                        TestId = "ReaderNotOnCorrectElement",
                    }
                };

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(WriteRequestedProofTokenTestCases))]
        public void WriteRequestedProofToken(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteRequestedProofToken", theoryData);
            try
            {
                WsTrustSerializer.WriteRequestedProofToken(theoryData.Writer, theoryData.WsSerializationContext, theoryData.RequestedProofToken);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteRequestedProofTokenTestCases
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        RequestedProofToken = new RequestedProofToken(),
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        RequestedProofToken = new RequestedProofToken(),
                        TestId = "WriterNull",
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("requestedProofToken"),
                        TestId = "RequestedProofTokenNull"
                    }
                };
            }
        }
    }
}
