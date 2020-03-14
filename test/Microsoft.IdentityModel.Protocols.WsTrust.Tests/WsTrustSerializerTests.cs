using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.TestUtils;
using Xunit;


#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class WsTrustSerializerTests
    {
        [Fact]
        public void Constructors()
        {
            TestUtilities.WriteHeader($"{this}.Constructors");
            CompareContext context = new CompareContext("Constructors");
            WsTrustSerializer wsTrustSerializer = new WsTrustSerializer();

            if (wsTrustSerializer.SecurityTokenHandlers.Count != 2)
                context.AddDiff("wsTrustSerializer.SecurityTokenHandlers.Count != 2");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(ReadLifetimeTheoryData))]
        public void ReadLifetime(WsTrustSerializerTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadLifetime", theoryData);
            try
            {
                var lifetime = theoryData.WsTrustSerializer.ReadLifetime(theoryData.Reader, theoryData.WsSerializationContext);
                IdentityComparer.AreEqual(lifetime, theoryData.Lifetime, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustSerializerTheoryData> ReadLifetimeTheoryData
        {
            get
            {
                return new TheoryData<WsTrustSerializerTheoryData>
                {
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("reader"),
                        TestId = "ReaderNull",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        Lifetime = new Lifetime(XmlConvert.ToDateTime("2017-04-23T16:11:17.348Z", XmlDateTimeSerializationMode.Utc), XmlConvert.ToDateTime("2017-04-23T17:11:17.348Z", XmlDateTimeSerializationMode.Utc)),
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetLifeTime("t", @"xmlns:t=""http://schemas.xmlsoap.org/ws/2005/02/trust""", "2017-04-23T16:11:17.348Z", "2017-04-23T17:11:17.348Z")),
                        TestId = "Lifetime",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.TrustFeb2005)
                    }
                };
            }
        }
    }

    public class WsTrustSerializerTheoryData : TheoryDataBase
    {
        public Lifetime Lifetime { get; set; }

        public WsSerializationContext WsSerializationContext { get; set; }

        public WsTrustSerializer WsTrustSerializer { get; set; } = new WsTrustSerializer();

        public XmlDictionaryReader Reader { get; set; }
    }
}
