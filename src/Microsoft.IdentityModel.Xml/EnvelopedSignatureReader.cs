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
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Wraps a reader pointing to a root element of enveloped signed XML.
    /// The signature and keyinfo will be read for signature validation.
    /// </summary>
    public class EnvelopedSignatureReader : DelegatingXmlDictionaryReader
    {
        private bool _disposed;
        private int _elementCount;
        private Signature _signature;
        private TokenStreamingReader _tokenStreamingReader;

        /// <summary>
        /// Initializes an instance of <see cref="EnvelopedSignatureReader"/>
        /// </summary>
        /// <param name="reader">Reader pointing to the enveloped signed XML.</param>
        public EnvelopedSignatureReader(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));


            _tokenStreamingReader = new TokenStreamingReader(CreateDictionaryReader(reader));
            InnerReader = _tokenStreamingReader;
            _tokenStreamingReader.XmlTokens.SetElementExclusion(XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace);
        }

        protected virtual void OnEndOfRootElement()
        {
            if (_signature != null)
                _signature.TokenSource = _tokenStreamingReader;
        }

        public Signature Signature { get { return _signature; } }

        /// <summary>
        /// Gets a XmlBuffer of the envelope that was enveloped signed.
        /// The buffer is available after the XML has been read and
        /// signature validated.
        /// </summary>
        public XmlTokenStream XmlTokens
        {
            get { return _tokenStreamingReader.XmlTokens.Trim(); }
        }

        /// <summary>
        /// If end of the envelope is reached, reads and validates the signature.
        /// </summary>
        /// <returns>true if the next node was read successfully; false if there are no more nodes</returns>
        public override bool Read()
        {
            if ((NodeType == XmlNodeType.Element) && (!base.IsEmptyElement))
                _elementCount++;

            if (NodeType == XmlNodeType.EndElement)
            {
                _elementCount--;
                if (_elementCount == 0)
                    OnEndOfRootElement();
            }

            bool result = base.Read();
            if (result
                && _signature == null
                && _tokenStreamingReader.IsLocalName(XmlSignatureConstants.Elements.Signature)
                && _tokenStreamingReader.IsNamespaceUri(XmlSignatureConstants.Namespace))
            {
                ReadSignature();
            }

            return result;
        }

        void ReadSignature()
        {
            _signature = new Signature(new SignedInfo());
            _signature.ReadFrom(_tokenStreamingReader);
            if (_signature.SignedInfo.ReferenceCount != 1)
                throw XmlUtil.LogReadException(LogMessages.IDX21101, _signature.SignedInfo.ReferenceCount);
        }

        /// <summary>
        /// Reads the signature if the reader is currently positioned at a Signature element.
        /// </summary>
        /// <returns>true if the signature was successfully read else false.</returns>
        /// <remarks>Does not move the reader when returning false.</remarks>
        public bool TryReadSignature()
        {
            if (IsStartElement(XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace))
            {
                ReadSignature();
                return true;
            }
            return false;
        }

        #region IDisposable Members

        /// <summary>
        /// Releases the unmanaged resources used by the System.IdentityModel.Protocols.XmlSignature.EnvelopedSignatureReader and optionally
        /// releases the managed resources.
        /// </summary>
        /// <param name="disposing">
        /// True to release both managed and unmanaged resources; false to release only unmanaged resources.
        /// </param>
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

                if (_tokenStreamingReader != null)
                {
                    _tokenStreamingReader.Close();
                    _tokenStreamingReader = null;
                }
            }

            // Free native resources, if any.

            _disposed = true;
        }

        #endregion
    }
}
