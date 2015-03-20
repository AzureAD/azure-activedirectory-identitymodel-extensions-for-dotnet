using System;
using System.Diagnostics.Tracing;
using System.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Logging.Tests
{
    public class LoggerTests
    {

        [Fact(DisplayName = "LoggerTests : NullArgumentException")]
        public void NullArgumentException()
        {
            SampleListener listener = new SampleListener();
            listener.EnableEvents(WilsonEventSource.Logger, EventLevel.Verbose);

            try
            {
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                SecurityToken token;
                handler.ValidateToken(null, null, out token);
            }
            catch (Exception ex)
            {
                Assert.Equal(ex.GetType(), typeof(ArgumentNullException));
                Assert.Contains(listener.TraceBuffer, "The parameter securityToken cannot be a 'null' or an empty string.");
            }
        }

    }

    class SampleListener : EventListener
    {
        public string TraceBuffer { get; set; }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            TraceBuffer += eventData.Payload[0];
        }
    }
}
