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
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    public class HashStream : Stream
    {
        private bool _disposed;
        private HashAlgorithm _hash;
        private bool _hashNeedsReset;
        private long _length;
        private MemoryStream _logStream;

        /// <summary>
        /// Constructor for HashStream. The HashAlgorithm instance is owned by the caller.
        /// </summary>
        public HashStream(HashAlgorithm hash)
        {
            if (hash == null)
                throw LogHelper.LogArgumentNullException(nameof(hash));

            Reset(hash);
        }

        public override bool CanRead
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public HashAlgorithm Hash
        {
            get { return _hash; }
        }

        public override long Length
        {
            get { return Position; }
        }

        public override long Position { get; set; }

        public override void Flush()
        {
        }

        public void FlushHash()
        {
            FlushHash(null);
        }

        public void FlushHash(MemoryStream preCanonicalBytes)
        {
            // TODO - optimize don't create new array each time
            _hash.TransformFinalBlock(new byte[0], 0, 0);
            IdentityModelEventSource.Logger.WriteInformation(string.Format($"logStream: '{_logStream}', hash: '{_hash}'."));
        }

        public byte[] FlushHashAndGetValue()
        {
            return FlushHashAndGetValue(null);
        }

        public byte[] FlushHashAndGetValue(MemoryStream preCanonicalBytes)
        {
            FlushHash(preCanonicalBytes);
            return _hash.Hash;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        public void Reset()
        {
            if (_hashNeedsReset)
            {
                _hash.Initialize();
                _hashNeedsReset = false;
            }
            _length = 0;
            _logStream = new MemoryStream();
        }

        public void Reset(HashAlgorithm hash)
        {
            _hash = hash;
            _hashNeedsReset = false;
            _length = 0;
            _logStream = new MemoryStream();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _hash.TransformBlock(buffer, offset, count, buffer, offset);
            _length += count;
            _hashNeedsReset = true;
            _logStream.Write(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        public override void SetLength(long length)
        {
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        #region IDisposable members

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                //
                // Free all of our managed resources
                //

                if (_logStream != null)
                {
                    _logStream.Dispose();
                    _logStream = null;
                }
            }

            // Free native resources, if any.
            _disposed = true;
        }

        #endregion
    }
}
