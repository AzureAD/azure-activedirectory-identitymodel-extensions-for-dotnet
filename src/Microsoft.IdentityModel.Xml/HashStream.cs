//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    public class HashStream : Stream
    {
        HashAlgorithm _hash;
        long _length;
        bool _disposed;
        bool _hashNeedsReset;
        MemoryStream _logStream;

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
            get { return _length; }
        }

        public override long Position
        {
            get { return _length; }
            set { _length = value; }
        }

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
