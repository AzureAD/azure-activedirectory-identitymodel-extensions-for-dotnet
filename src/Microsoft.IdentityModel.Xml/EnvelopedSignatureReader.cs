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
    /// Wraps a reader pointing to a enveloped signed XML and provides
    /// a reader that can be used to read the content without having to
    /// process the signature. The Signature is automatically validated
    /// when the last element of the envelope is read.
    /// </summary>
    public sealed class EnvelopedSignatureReader : DelegatingXmlDictionaryReader
    {
        int _elementCount;
        bool _requireSignature;
        SigningCredentials _signingCredentials;
        SignedXml _signedXml;
        WrappedReader _wrappedReader;
        bool _disposed;

        /// <summary>
        /// Initializes an instance of <see cref="EnvelopedSignatureReader"/>
        /// </summary>
        /// <param name="reader">Reader pointing to the enveloped signed XML.</param>
        public EnvelopedSignatureReader(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            _requireSignature = true;
            _wrappedReader = new WrappedReader(CreateDictionaryReader(reader));
            SetCanonicalizingReader(_wrappedReader);
        }

        void OnEndOfRootElement()
        {
            if (_signedXml == null && _requireSignature)
                throw LogHelper.LogExceptionMessage(new CryptographicException("SR.ID3089"));

            if (_signedXml != null)
            {
                ResolveSigningCredentials();
                _signedXml.StartSignatureVerification(_signingCredentials.Key);
                _wrappedReader.XmlTokens.SetElementExclusion(XmlSignatureStrings.Signature, XmlSignatureStrings.Namespace);
                WifSignedInfo signedInfo = _signedXml.Signature.SignedInfo as WifSignedInfo;
                _signedXml.EnsureDigestValidity(signedInfo[0].ExtractReferredId(), _wrappedReader);
                _signedXml.CompleteSignatureVerification();
            }
        }

        /// <summary>
        /// Returns the SigningCredentials used in the signature after the 
        /// envelope is consumed and when the signature is validated.
        /// </summary>
        public SigningCredentials SigningCredentials
        {
            get
            {
                return _signingCredentials;
            }
        }

        /// <summary>
        /// Gets a XmlBuffer of the envelope that was enveloped signed.
        /// The buffer is available after the XML has been read and
        /// signature validated.
        /// </summary>
        public XmlTokenStream XmlTokens
        {
            get
            {
                return _wrappedReader.XmlTokens.Trim();
            }
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
                // TODO - read signature to be processed later
                //if (_elementCount == 0)
                //    OnEndOfRootElement();
            }

            bool result = base.Read();
            if (result
                && _signedXml == null
                && InnerReader.IsLocalName(XmlSignatureStrings.Signature)
                && InnerReader.IsNamespaceUri(XmlSignatureStrings.Namespace))
            {
                ReadSignature();
            }

            return result;
        }

        void ReadSignature()
        {
            _signedXml = new SignedXml(new WifSignedInfo());
            _signedXml.TransformFactory = TransformFactory.Instance;
            _signedXml.ReadFrom(_wrappedReader);
            if (_signedXml.Signature.SignedInfo.ReferenceCount != 1)
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("SR.ID3057"));
            }
        }

        void ResolveSigningCredentials()
        {
            if (_signedXml.Signature == null || _signedXml.Signature.Key == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException("ID3276"));

            _signingCredentials = new SigningCredentials(_signedXml.Signature.Key, _signedXml.Signature.SignedInfo.SignatureMethod);
        }

        /// <summary>
        /// Reads the signature if the reader is currently positioned at a Signature element.
        /// </summary>
        /// <returns>true if the signature was successfully read else false.</returns>
        /// <remarks>Does not move the reader when returning false.</remarks>
        public bool TryReadSignature()
        {
            if (IsStartElement(XmlSignatureStrings.Signature, XmlSignatureStrings.Namespace))
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

                if (_wrappedReader != null)
                {
                    _wrappedReader.Close();
                    _wrappedReader = null;
                }
            }

            // Free native resources, if any.

            _disposed = true;
        }

        #endregion
    }
}
