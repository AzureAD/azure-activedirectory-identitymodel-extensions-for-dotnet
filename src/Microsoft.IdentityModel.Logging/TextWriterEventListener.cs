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
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.MIML11000);
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
