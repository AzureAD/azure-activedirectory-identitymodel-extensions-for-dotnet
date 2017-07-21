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
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Wraps a <see cref="XmlWriter"/> and generates a signature automatically when the envelope
    /// is written completely. By default the generated signature is inserted as
    /// the last element in the envelope. This can be modified by explicitly
    /// calling WriteSignature to indicate the location inside the envelope where
    /// the signature should be inserted.
    /// </summary>
    public sealed class EnvelopedSignatureWriter : DelegatingXmlDictionaryWriter
    {
        private DSigSerializer _dsigSerializer = new DSigSerializer();
        private bool _disposed;
        private int _elementCount;
        private string _referenceId;
        private MemoryStream _hashStream;
        private SigningCredentials _signingCredentials;
        private MemoryStream _writerStream;

        /// <summary>
        /// Initializes an instance of <see cref="EnvelopedSignatureWriter"/>. The returned writer can be directly used
        /// to write the envelope. The signature will be automatically generated when 
        /// the envelope is completed.
        /// </summary>
        /// <param name="writer">Writer to wrap/</param>
        /// <param name="signingCredentials">SigningCredentials to be used to generate the signature.</param>
        /// <param name="referenceId">The reference Id of the envelope.</param>
        /// <exception cref="ArgumentNullException">if 'writer' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'signingCredentials' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'referenceId' is null or Empty.</exception>
        public EnvelopedSignatureWriter(XmlWriter writer, SigningCredentials signingCredentials, string referenceId)
        {
            if (writer == null)
                throw LogArgumentNullException(nameof(writer));

            if (string.IsNullOrEmpty(referenceId))
                throw LogArgumentNullException(nameof(referenceId));

            // the Signature will be written into the innerWriter.
            _signingCredentials = signingCredentials ?? throw LogArgumentNullException(nameof(signingCredentials));
            _referenceId = referenceId;
            _writerStream = new MemoryStream();
            _hashStream = new MemoryStream();

            InnerWriter = CreateTextWriter(_writerStream, Encoding.UTF8, false);
            InnerWriter.StartCanonicalization(_hashStream, false, null);
            TracingWriter = CreateDictionaryWriter(writer);
        }

        private void OnEndRootElement()
        {
            InnerWriter.WriteEndElement();
            InnerWriter.Flush();
            InnerWriter.EndCanonicalization();
            var hashAlgorithm = _signingCredentials.Key.CryptoProviderFactory.CreateHashAlgorithm(_signingCredentials.Digest);
            var reference = new Reference
            {
                Id = _referenceId,
                DigestValue = Convert.ToBase64String(hashAlgorithm.ComputeHash(_hashStream)),
                DigestMethod = _signingCredentials.Digest
            };

            var signedInfo = new SignedInfo(reference)
            {
                CanonicalizationMethod = SecurityAlgorithms.ExclusiveC14n,
                SignatureMethod = _signingCredentials.Algorithm
            };

            var stream = new MemoryStream();
            var writer = CreateTextWriter(Stream.Null);
            var includeComments = signedInfo.CanonicalizationMethod == SecurityAlgorithms.ExclusiveC14nWithComments;
            writer.StartCanonicalization(stream, includeComments, null);
            _dsigSerializer.WriteSignedInfo(writer, signedInfo);
            writer.EndCanonicalization();
            writer.Flush();
            stream.Position = 0;
            var xml = Encoding.UTF8.GetString(stream.ToArray());

            var provider = _signingCredentials.Key.CryptoProviderFactory.CreateForSigning(_signingCredentials.Key, signedInfo.SignatureMethod);
#if DEBUG
            var signatureBytes = provider.Sign(stream.ToArray());
#endif
            var signature = new Signature
            {
                KeyInfo = new KeyInfo(_signingCredentials.Key),
                SignatureValue = Convert.ToBase64String(provider.Sign(stream.ToArray())),
                SignedInfo = signedInfo,
            };

            _dsigSerializer.WriteSignature(TracingWriter, signature);

            TracingWriter.WriteEndElement();
            TracingWriter.Flush();
        }

        /// <summary>
        /// Sets the position of the signature within the envelope. Call this
        /// method while writing the envelope to indicate at which point the 
        /// signature should be inserted.
        /// </summary>
        public void WriteSignature()
        {
        }

        /// <summary>
        /// Overrides the base class implementation. When the last element of the envelope is written
        /// the signature is automatically computed over the envelope and the signature is inserted at
        /// the appropriate position, if WriteSignature was explicitly called or is inserted at the
        /// end of the envelope.
        /// </summary>
        public override void WriteEndElement()
        {
            _elementCount--;
            if (_elementCount == 0)
            {
                base.Flush();
                OnEndRootElement();
            }
            else
            {
                base.WriteEndElement();
            }
        }

        /// <summary>
        /// Overrides the base class implementation. When the last element of the envelope is written
        /// the signature is automatically computed over the envelope and the signature is inserted at
        /// the appropriate position, if WriteSignature was explicitly called or is inserted at the
        /// end of the envelope.
        /// </summary>
        public override void WriteFullEndElement()
        {
            _elementCount--;
            if (_elementCount == 0)
            {
                base.Flush();
                OnEndRootElement();
            }
            else
            {
                base.WriteFullEndElement();
            }
        }

        /// <summary>
        /// Overrides the base class. Writes the specified start tag and associates
        /// it with the given namespace.
        /// </summary>
        /// <param name="prefix">The namespace prefix of the element.</param>
        /// <param name="localName">The local name of the element.</param>
        /// <param name="namespace">The namespace URI to associate with the element.</param>
        public override void WriteStartElement(string prefix, string localName, string @namespace)
        {
            _elementCount++;
            base.WriteStartElement(prefix, localName, @namespace);
        }

        #region IDisposable Members

        /// <summary>
        /// Releases the unmanaged resources used by the System.IdentityModel.Protocols.XmlSignature.EnvelopedSignatureWriter and optionally
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

            _disposed = true;

            if (disposing)
            {
                if (_writerStream != null)
                {
                    _writerStream.Dispose();
                    _writerStream = null;
                }

                if (_hashStream != null)
                {
                    _hashStream.Dispose();
                    _hashStream = null;
                }
            }
        }

        #endregion
    }
}
