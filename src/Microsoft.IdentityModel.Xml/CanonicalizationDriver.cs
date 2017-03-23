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
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    public sealed class CanonicalizationDriver
    {
        XmlReader _reader;
        string[] _inclusivePrefixes;

        public bool CloseReadersAfterProcessing { get; set; }

        public bool IncludeComments { get; set; }

        public string[] GetInclusivePrefixes()
        {
            return _inclusivePrefixes;
        }

        public void Reset()
        {
            _reader = null;
        }

        public void SetInclusivePrefixes(string[] inclusivePrefixes)
        {
            _inclusivePrefixes = inclusivePrefixes;
        }

        public void SetInput(Stream stream)
        {
            if (stream == null)
                throw LogHelper.LogArgumentNullException(nameof(stream));

            _reader = XmlReader.Create(stream);
        }

        public void SetInput(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            _reader = reader;
        }

        public byte[] GetBytes()
        {
            return GetMemoryStream().ToArray();
        }

        public MemoryStream GetMemoryStream()
        {
            MemoryStream stream = new MemoryStream();
            WriteTo(stream);
            stream.Seek(0, SeekOrigin.Begin);
            return stream;
        }

        public void WriteTo(Stream canonicalStream)
        {
            if (_reader != null)
            {
                XmlDictionaryReader dicReader = _reader as XmlDictionaryReader;
                if ((dicReader != null) && (dicReader.CanCanonicalize))
                {
                    dicReader.MoveToContent();
                    dicReader.StartCanonicalization(canonicalStream, IncludeComments, _inclusivePrefixes);
                    dicReader.Skip();
                    dicReader.EndCanonicalization();
                }
                else
                {
                    XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(Stream.Null);
                    if (_inclusivePrefixes != null)
                    {
                        // Add a dummy element at the top and populate the namespace 
                        // declaration of all the inclusive prefixes.
                        writer.WriteStartElement("a", _reader.LookupNamespace(string.Empty));
                        for (int i = 0; i < _inclusivePrefixes.Length; ++i)
                        {
                            string ns = _reader.LookupNamespace(_inclusivePrefixes[i]);
                            if (ns != null)
                            {
                                writer.WriteXmlnsAttribute(_inclusivePrefixes[i], ns);
                            }
                        }
                    }
                    writer.StartCanonicalization(canonicalStream, IncludeComments, _inclusivePrefixes);
                    if (_reader is WrappedReader)
                        ((WrappedReader)_reader).XmlTokens.GetWriter().WriteTo(writer);
                    else

                        writer.WriteNode(_reader, false);

                    writer.Flush();
                    writer.EndCanonicalization();

                    if (_inclusivePrefixes != null)
                        writer.WriteEndElement();

                    writer.Close();
                }
                if (CloseReadersAfterProcessing)
                    _reader.Close();

                _reader = null;
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new InvalidOperationException("NoInputIsSetForCanonicalization"));
            }
        }
    }

}
