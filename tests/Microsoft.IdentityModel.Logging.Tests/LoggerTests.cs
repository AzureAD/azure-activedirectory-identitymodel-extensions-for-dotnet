using System;
using System.Diagnostics.Tracing;
using System.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Logging.Tests
{
    public class LoggerTests
    {

        [Fact(DisplayName = "LoggerTests : LogMessageAndThrowException")]
        public void LogMessageAndThrowException()
        {
            SampleListener listener = new SampleListener();
            IdentityModelEventSource.LogLevel = EventLevel.Verbose;             // since null parameters exceptions are logged at Verbose level
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Verbose);

            try
            {
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                SecurityToken token;

                // This should log an error and throw null argument exception.
                handler.ValidateToken(null, null, out token);
            }
            catch (Exception ex)
            {
                Assert.Equal(ex.GetType(), typeof(ArgumentNullException));
                Assert.Contains("securityToken' cannot be a 'null' or an empty string.", listener.TraceBuffer);
            }
        }

        [Fact(DisplayName = "LogggerTests : LogMessage")]
        public void LogMessage()
        {
            SampleListener listener = new SampleListener();
            IdentityModelEventSource.LogLevel = EventLevel.Warning;
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Verbose);

            TokenValidationParameters validationParameters = new TokenValidationParameters()
            {
                ValidateAudience = false
            };

            // This should log a warning about not validating the audience
            Validators.ValidateAudience(null, null, validationParameters);
            Assert.Contains("ValidateAudience property on ValidationParamaters is set to false. Exiting without validating the audience.", listener.TraceBuffer);
        }

        [Fact(DisplayName = "LoggerTests : TestLogLevel")]
        public void TestLogLevel()
        {
            SampleListener listener = new SampleListener();
            IdentityModelEventSource.LogLevel = EventLevel.Informational;
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Verbose);

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            handler.CreateToken();

            // This is Informational level message. Should be there in the trace buffer since default log level is informational.
            Assert.Contains("Creating security token from the header, payload and raw signature.", listener.TraceBuffer);
            // This is Verbose level message. Should not be there in the trace buffer.
            Assert.DoesNotContain("Creating payload and header from the passed parameters including issuer, audience, signing credentials and others.", listener.TraceBuffer);

            // Setting log level to verbose so that all messages are logged.
            IdentityModelEventSource.LogLevel = EventLevel.Verbose;
            handler.CreateToken();
            Assert.Contains("Creating security token from the header, payload and raw signature.", listener.TraceBuffer);
            Assert.Contains("Creating payload and header from the passed parameters including issuer, audience, signing credentials and others.", listener.TraceBuffer);

        }
    }

    class SampleListener : EventListener
    {
        public string TraceBuffer { get; set; }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            TraceBuffer += eventData.Payload[0] + "\n";
        }
    }
}
