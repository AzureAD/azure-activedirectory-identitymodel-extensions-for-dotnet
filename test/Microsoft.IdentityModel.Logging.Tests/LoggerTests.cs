//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System;
using System.Diagnostics.Tracing;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens.Tests;
using System.IO;
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
                Assert.Contains("IDX10000: The parameter 'System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler: securityToken' cannot be a 'null' or an empty object.", listener.TraceBuffer);
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
            Assert.Contains("IDX10233: ", listener.TraceBuffer);
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
            Assert.Contains("IDX10722: ", listener.TraceBuffer);
            // This is Verbose level message. Should not be there in the trace buffer.
            Assert.DoesNotContain("IDX10721: ", listener.TraceBuffer);

            // Setting log level to verbose so that all messages are logged.
            IdentityModelEventSource.LogLevel = EventLevel.Verbose;
            handler.CreateToken();
            Assert.Contains("IDX10722: ", listener.TraceBuffer);
            Assert.Contains("IDX10721: ", listener.TraceBuffer);

        }

        [Fact(DisplayName = "LoggerTests: Test TextWriterEventListener")]
        public void TextWriterEventListenerLogging()
        {
            IdentityModelEventSource.LogLevel = EventLevel.Informational;
            using (TextWriterEventListener listener = new TextWriterEventListener("testLog.txt"))
            {
                listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Verbose);

                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                JwtSecurityToken jwt = tokenHandler.CreateToken(
                    IdentityUtilities.DefaultIssuer,
                    IdentityUtilities.DefaultAudience,
                    ClaimSets.DefaultClaimsIdentity,
                    DateTime.UtcNow,
                    DateTime.UtcNow + TimeSpan.FromHours(1),
                    IdentityUtilities.DefaultAsymmetricSigningCredentials);


                TokenValidationParameters validationParameters =
                    new TokenValidationParameters()
                    {
                        IssuerSigningKey = IdentityUtilities.DefaultAsymmetricSigningKey,
                        ValidAudience = IdentityUtilities.DefaultAudience,
                        ValidIssuer = IdentityUtilities.DefaultIssuer,
                    };
                SecurityToken securityToken;
                tokenHandler.ValidateToken(jwt.RawData, validationParameters, out securityToken);
            }

            string logText = File.ReadAllText("testLog.txt");
            Assert.Contains("IDX10239: ", logText);
            Assert.Contains("IDX10244: ", logText);
            Assert.Contains("IDX10240: ", logText);
            Assert.Contains("IDX10236: ", logText);
            Assert.Contains("IDX10245: ", logText);

            File.Delete("testLog.txt");
        }

        [Fact(DisplayName = "LoggerTests: Test TextWriterEventListener with access denied to file.")]
        public void TextListenerCantAccessFileToWrite()
        {
            SampleListener listener = new SampleListener();
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Informational);

            // default log file cannot be accessed because it is in use. Should throw an IO exception.
            FileStream fileStream = File.Create(TextWriterEventListener.DefaultLogFileName);
            Assert.Throws<IOException>(() => { new TextWriterEventListener();  });
            Assert.Contains("MIML11001: ", listener.TraceBuffer);
            fileStream.Dispose();
            File.Delete(TextWriterEventListener.DefaultLogFileName);

            // file specified by user cannot be accessed.
            string fileName = "testLog.txt";
            fileStream = File.Create(fileName);
            FileInfo fileInfo = new FileInfo(fileName);
            fileInfo.IsReadOnly = true;
            Assert.Throws<UnauthorizedAccessException>(() => { new TextWriterEventListener(fileName); });
            fileInfo.IsReadOnly = false;
            fileStream.Dispose();
            File.Delete(fileName);

        }
        [Fact(DisplayName = "LoggerTests: Testing TextWriterEventListener Constructors ")]
        public void TextWriterEventListenerConstructors()
        {
            // using defaults
            using (TextWriterEventListener listener = new TextWriterEventListener())
            {
                listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Informational);
                IdentityModelEventSource.Logger.WriteWarning("This is a warning!");
            }
            string logText = File.ReadAllText(TextWriterEventListener.DefaultLogFileName);
            Assert.Contains("This is a warning!", logText);
            File.Delete(TextWriterEventListener.DefaultLogFileName);

            // passing custom file path
            using (TextWriterEventListener listener = new TextWriterEventListener("testLog.txt"))
            {
                listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Informational);
                IdentityModelEventSource.Logger.WriteWarning("This is a warning for custom file path!");
            }
            logText = File.ReadAllText("testLog.txt");
            Assert.Contains("This is a warning for custom file path!", logText);
            File.Delete("testLog.txt");

            // using StreamWriter
            Stream fileStream = new FileStream("testLog.txt", FileMode.OpenOrCreate, FileAccess.Write);
            StreamWriter streamWriter = new StreamWriter(fileStream);
            using (TextWriterEventListener listener = new TextWriterEventListener(streamWriter))
            {
                listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Informational);
                IdentityModelEventSource.Logger.WriteWarning("This is a warning for streamwriter!");
            }
            streamWriter.Dispose();
            logText = File.ReadAllText("testLog.txt");
            Assert.Contains("This is a warning for streamwriter!", logText);
            File.Delete("testLog.txt");
        }


    }

    class SampleListener : EventListener
    {
        public string TraceBuffer { get; set; }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if (eventData != null && eventData.Payload.Count > 0)
            {
                TraceBuffer += eventData.Payload[0] + "\n";
            }
        }
    }
}
