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
using System.Globalization;
using System.IO;

namespace Microsoft.IdentityModel.Logging
{
    /// <summary>
    /// Event listener that writes logs to a file or a fileStream provided by user.
    /// </summary>
    public class TextWriterEventListener : EventListener
    {
        private StreamWriter _streamWriter;
        private bool _disposeStreamWriter = true;

        public readonly static string DefaultLogFileName = "IdentityModelLogs.txt";

        public TextWriterEventListener()
        {
            try
            {
                Stream fileStream = new FileStream(DefaultLogFileName, FileMode.OpenOrCreate, FileAccess.Write);
                _streamWriter = new StreamWriter(fileStream);
                _streamWriter.AutoFlush = true;
            }
            catch (Exception ex)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.MIML11001, ex.Message), ex.GetType(), EventLevel.Error, ex.InnerException);
            }
        }

        /// <summary>
        /// Constructor for TextWriterEventListener.
        /// </summary>
        /// <param name="filePath">location of the file where all log messages will be written.</param>
        public TextWriterEventListener(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.MIML10000, GetType() + ": filePath"), typeof(ArgumentNullException), EventLevel.Verbose);
            }
            Stream fileStream = new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.Write);
            _streamWriter = new StreamWriter(fileStream);
            _streamWriter.AutoFlush = true;
        }

        /// <summary>
        /// Constructor for TextWriterEventListener.
        /// </summary>
        /// <param name="streamWriter">StreamWriter that writes log messages.</param>
        public TextWriterEventListener(StreamWriter streamWriter)
        {
            if (streamWriter == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.MIML10000, GetType() + ": streamWriter"), typeof(ArgumentNullException), EventLevel.Verbose);
            }
            _streamWriter = streamWriter;
            _disposeStreamWriter = false;
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if (eventData == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.MIML10000, GetType() + ": eventData"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (eventData.Payload == null || eventData.Payload.Count <= 0)
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.MIML10000);
                return;
            }

            for (int i = 0; i < eventData.Payload.Count; i++)
            {
                _streamWriter.WriteLine(eventData.Payload[i].ToString());
            }
        }

        public override void Dispose()
        {
            if (_disposeStreamWriter)
            {
                _streamWriter.Flush();
                _streamWriter.Dispose();
            }
            base.Dispose();
        }
    }
}
