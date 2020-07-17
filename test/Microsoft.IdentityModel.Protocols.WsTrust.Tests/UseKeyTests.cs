using System;
using System.IO;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class UseKeyTests
    {
        [Theory, MemberData(nameof(ReadUseKeyTheoryData))]
        public void ReadUseKey(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadUseKey", theoryData);

            try
            {
                var useKey = WsTrustSerializer.ReadUseKey(theoryData.Reader, theoryData.WsSerializationContext);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(useKey, theoryData.UseKey, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadUseKeyTheoryData
        {
            get
            {
                var theoryData = new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(ReferenceXml.RandomElementReader)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
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
                        Reader = ReferenceXml.RandomElementReader,
                        TestId = "ReaderNotOnCorrectElement",
                    }
                };

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(WriteUseKeyTheoryData))]
        public void WriteUseKey(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteUseKey", theoryData);
            try
            {
                WsTrustSerializer.WriteUseKey(theoryData.Writer, theoryData.WsSerializationContext, theoryData.UseKey);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteUseKeyTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        UseKey = new UseKey(new SecurityTokenElement(new SecurityTokenReference())),
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        UseKey = new UseKey(new SecurityTokenElement(new SecurityTokenReference())),
                        TestId = "WriterNull",
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("useKey"),
                        TestId = "UseKeyNull"
                    }
                };
            }
        }
    }
}
