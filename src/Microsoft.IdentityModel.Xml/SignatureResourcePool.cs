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
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    // For sequential use by one thread, so reusable objects are only created once.
    // The model for use is the upper layer that Verifies a signature will create a new SignatureResourcePool
    internal class SignatureResourcePool
    {
        private char[] _base64Buffer;
        private const int _bufferSize = 64;
        private CanonicalizationDriver _canonicalizationDriver;
        private byte[] _encodingBuffer;
        private HashStream _hashStream;
        private XmlDictionaryWriter _utf8Writer;

        public char[] TakeBase64Buffer()
        {
            if (_base64Buffer == null)
                _base64Buffer = new char[_bufferSize];

            return _base64Buffer;
        }

        public CanonicalizationDriver TakeCanonicalizationDriver(XmlReader reader, bool includeComments, string[] inclusivePrefixes)
        {
            if (_canonicalizationDriver == null)
                _canonicalizationDriver = new CanonicalizationDriver();
            else
                _canonicalizationDriver.Reset();

            _canonicalizationDriver.IncludeComments = includeComments;
            _canonicalizationDriver.SetInclusivePrefixes(inclusivePrefixes);
            _canonicalizationDriver.SetInput(reader);

            return _canonicalizationDriver;
        }

        public byte[] TakeEncodingBuffer()
        {
            if (_encodingBuffer == null)
                _encodingBuffer = new byte[_bufferSize];

            return _encodingBuffer;
        }

        public HashStream TakeHashStream(HashAlgorithm hash)
        {
            if (_hashStream == null)
                _hashStream = new HashStream(hash);
            else
                _hashStream.Reset(hash);

            return _hashStream;
        }

        public XmlDictionaryWriter TakeUtf8Writer()
        {
            if (_utf8Writer == null)
                _utf8Writer = XmlDictionaryWriter.CreateTextWriter(Stream.Null, Encoding.UTF8, false);
            else
                ((IXmlTextWriterInitializer)_utf8Writer).SetOutput(Stream.Null, Encoding.UTF8, false);

            return _utf8Writer;
        }
    }
}
