using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Logging.Tests
{
    public class IdentityModelTelemetryParametersTests
    {
        [Theory, MemberData(nameof(SetTelemetryDataTheoryData), DisableDiscoveryEnumeration = true)]
        public void SetTelemetry(TelemetryTheoryData theoryData)
        {
            var testContext = new CompareContext();

            try
            {
                IdentityModelTelemetryParameters.SetTelemetryData(theoryData.HttpRequestMessage);
                // check if the resulting headers are as expected
                if (!IdentityComparer.AreEqual(theoryData.ExpectedHeaders, theoryData.HttpRequestMessage?.Headers))
                    throw new ArgumentException("resulting headers are not matching the expected headers.");

                theoryData.ExpectedException.ProcessNoException(testContext);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, testContext);
            }

            TestUtilities.AssertFailIfErrors(testContext);
        }

        public static TheoryData<TelemetryTheoryData> SetTelemetryDataTheoryData
        {
            get
            {
                return new TheoryData<TelemetryTheoryData>
                {
                    new TelemetryTheoryData
                    {
                        HttpRequestMessage = null,
                        TestId = "nullRequestMessage"
                    },
                    new TelemetryTheoryData
                    {
                        HttpRequestMessage = BuildHttpRequestMessage(),
                        ExpectedHeaders = BuildHttpRequestHeaders(),
                        TestId = "noAdditionalHeaders"
                    },
                    new TelemetryTheoryData
                    {
                        HttpRequestMessage = BuildHttpRequestMessage(new Dictionary<string, string> { {"header1", "value1"} }),
                        ExpectedHeaders = BuildHttpRequestHeaders(new Dictionary<string, string> { {"header1", "value1"} }),
                        TestId = "withAdditionalHeaders"
                    },
                    new TelemetryTheoryData
                    {
                        HttpRequestMessage = BuildHttpRequestMessage(new Dictionary<string, string> { { IdentityModelTelemetryParameters.skuTelemetry, "some-other-value"} }),
                        ExpectedHeaders = BuildHttpRequestHeaders(),
                        TestId = "overwriteExistingHeaders"
                    },
                    new TelemetryTheoryData
                    {
                        HttpRequestMessage = BuildHttpRequestMessage(new Dictionary<string, string> { { "header1", "value1" }, { IdentityModelTelemetryParameters.skuTelemetry, "some-other-value"}, {"header2", "value2"} }),
                        ExpectedHeaders = BuildHttpRequestHeaders(new Dictionary<string, string> { {"header1", "value1"}, {"header2", "value2"} }),
                        TestId = "overwriteExistingButKeepOtherHeaders"
                    }
                };
            }
        }

        [Fact]
        public void AddParameterTest()
        {
            IdentityModelTelemetryParameters.AddParameter("parameter1", "value1");
            Assert.True(IdentityModelTelemetryParameters.parameters.ContainsKey("parameter1") && IdentityModelTelemetryParameters.parameters["parameter1"] == "value1");
            IdentityModelTelemetryParameters.AddParameter("parameter1", "value2");
            Assert.True(IdentityModelTelemetryParameters.parameters.ContainsKey("parameter1") && IdentityModelTelemetryParameters.parameters["parameter1"] == "value2");

            Assert.Throws<ArgumentNullException>(() => IdentityModelTelemetryParameters.AddParameter(null, "value1"));
            Assert.Throws<ArgumentException>(() => IdentityModelTelemetryParameters.AddParameter(IdentityModelTelemetryParameters.skuTelemetry, "value1"));
            Assert.Throws<ArgumentException>(() => IdentityModelTelemetryParameters.AddParameter(IdentityModelTelemetryParameters.versionTelemetry, "value1"));

            IdentityModelTelemetryParameters.AddParameter("parameter1", null);
            Assert.True(!IdentityModelTelemetryParameters.parameters.ContainsKey("parameter1"));
        }

        [Fact]
        public void RemoveParameterTest()
        {
            IdentityModelTelemetryParameters.AddParameter("parameter1", "value1");
            Assert.True(IdentityModelTelemetryParameters.parameters.ContainsKey("parameter1") && IdentityModelTelemetryParameters.parameters["parameter1"] == "value1");
            IdentityModelTelemetryParameters.RemoveParameter("parameter1");
            Assert.True(!IdentityModelTelemetryParameters.parameters.ContainsKey("parameter1"));

            Assert.Throws<ArgumentNullException>(() => IdentityModelTelemetryParameters.RemoveParameter(null));
            Assert.Throws<ArgumentException>(() => IdentityModelTelemetryParameters.RemoveParameter(IdentityModelTelemetryParameters.skuTelemetry));
            Assert.Throws<ArgumentException>(() => IdentityModelTelemetryParameters.RemoveParameter(IdentityModelTelemetryParameters.versionTelemetry));
        }

        private static HttpRequestHeaders BuildHttpRequestHeaders(IDictionary<string, string> additionalHeaders = null, bool addDefaultTelemetryData = true)
        {
            var headers = new HttpClient().DefaultRequestHeaders;

            if (additionalHeaders != null)
            {
                foreach (var header in additionalHeaders)
                    headers.Add(header.Key, header.Value);
            }

            if (addDefaultTelemetryData)
            {
                foreach (var header in IdentityModelTelemetryParameters.parameters)
                    headers.Add(header.Key, header.Value);
            }

            return headers;
        }

        private static HttpRequestMessage BuildHttpRequestMessage(IDictionary<string, string> headers = null, string defaultUri = "https://gotJwt.onmicrosoft.com/signedIn")
        {
            var message = new HttpRequestMessage()
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri(defaultUri),
            };

            if (headers != null)
            {
                foreach (var header in headers)
                    message.Headers.Add(header.Key, header.Value);
            }

            return message;
        }

        public class TelemetryTheoryData : TheoryDataBase
        {
            public bool SendTelemetry { get; set; } = true;

            public HttpRequestMessage HttpRequestMessage { get; set; }

            public HttpRequestHeaders ExpectedHeaders { get; set; }
        }
    }

    /// <summary>
    /// Helper extension of <see cref="HttpRequestHeaders"/> class.
    /// </summary>
    public static class HttpRequestHeadersExtension
    {
        /// <summary>
        /// Clone <paramref name="headers"/> to a <see cref="IDictionary{String, strign}"/>.
        /// </summary>
        /// <param name="headers">Headers to clone to a <see cref="IDictionary{String, strign}"/></param>
        /// <returns>Cloned headers in form of a <see cref="IDictionary{String, strign}"/>.</returns>
        public static IDictionary<string, string> CloneToDictionary(this HttpRequestHeaders headers)
        {
            if (headers == null)
                return null;

            var result = new Dictionary<string, string>();

            foreach (var header in headers)
            {
                result.Add(header.Key, header.Value.First());
            }

            return result;
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
