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
        private MemoryStream _canonicalStream;
        private bool _disposed;
        private DSigSerializer _dsigSerializer = DSigSerializer.Default;
        private int _elementCount;
        private string _inclusivePrefixList;
        private XmlWriter _originalWriter;
        private string _referenceId;
        private long _signaturePosition;
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
        /// <exception cref="ArgumentNullException">if <paramref name="writer"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="signingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="referenceId"/> is null or Empty.</exception>
        public EnvelopedSignatureWriter(XmlWriter writer, SigningCredentials signingCredentials, string referenceId)
            : this(writer, signingCredentials, referenceId, null)
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="EnvelopedSignatureWriter"/>. The returned writer can be directly used
        /// to write the envelope. The signature will be automatically generated when
        /// the envelope is completed.
        /// </summary>
        /// <param name="writer">Writer to wrap/</param>
        /// <param name="signingCredentials">SigningCredentials to be used to generate the signature.</param>
        /// <param name="referenceId">The reference Id of the envelope.</param>
        /// <param name="inclusivePrefixList">inclusive prefix list to use for exclusive canonicalization.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="writer"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="signingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="referenceId"/> is null or Empty.</exception>
        public EnvelopedSignatureWriter(XmlWriter writer, SigningCredentials signingCredentials, string referenceId, string inclusivePrefixList)
        {
            _originalWriter = writer ?? throw LogArgumentNullException(nameof(writer));
            _signingCredentials = signingCredentials ?? throw LogArgumentNullException(nameof(signingCredentials));
            if (string.IsNullOrEmpty(referenceId))
                throw LogArgumentNullException(nameof(referenceId));

            _inclusivePrefixList = inclusivePrefixList;
            _referenceId = referenceId;
            _writerStream = new MemoryStream();
            _canonicalStream = new MemoryStream();
            InnerWriter = CreateTextWriter(_writerStream, Encoding.UTF8, false);
            InnerWriter.StartCanonicalization(_canonicalStream, false, XmlUtil.TokenizeInclusivePrefixList(_inclusivePrefixList);
            _signaturePosition = -1;
        }


        /// <summary>
        /// Gets or sets the <see cref="DSigSerializer"/> to use.
        /// </summary>
        /// <exception cref="ArgumentNullException">if value is null.</exception>
        public DSigSerializer DSigSerializer
        {
            get => _dsigSerializer;
            set => _dsigSerializer = value ?? throw LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Calculates and inserts the Signature.
        /// </summary>
        private void OnEndRootElement()
        {
            if (_signaturePosition == -1)
                WriteSignature();

            InnerWriter.WriteEndElement();
            InnerWriter.Flush();
            InnerWriter.EndCanonicalization();

            var signature = CreateSignature();
            var signatureStream = new MemoryStream();
            var signatureWriter = CreateTextWriter(signatureStream);
            DSigSerializer.WriteSignature(signatureWriter, signature);
            signatureWriter.Flush();
            var signatureBytes = signatureStream.ToArray();
            var writerBytes = _writerStream.ToArray();
            byte[] effectiveBytes = new byte[signatureBytes.Length + writerBytes.Length];
            Array.Copy(writerBytes, effectiveBytes, (int)_signaturePosition);
            Array.Copy(signatureBytes, 0, effectiveBytes, (int)_signaturePosition, signatureBytes.Length);
            Array.Copy(writerBytes, (int)_signaturePosition, effectiveBytes, (int)_signaturePosition + signatureBytes.Length, writerBytes.Length - (int)_signaturePosition);

            XmlReader reader = XmlDictionaryReader.CreateTextReader(effectiveBytes, XmlDictionaryReaderQuotas.Max);
            reader.MoveToContent();
            _originalWriter.WriteNode(reader, false);
            _originalWriter.Flush();
        }

        private Signature CreateSignature()
        {
            var hashAlgorithm = _signingCredentials.Key.CryptoProviderFactory.CreateHashAlgorithm(_signingCredentials.Digest);
            var reference = new Reference(new EnvelopedSignatureTransform(), new ExclusiveCanonicalizationTransform { InclusivePrefixList = _inclusivePrefixList })
            {
                Id = _referenceId,
                DigestValue = Convert.ToBase64String(hashAlgorithm.ComputeHash(_canonicalStream.ToArray())),
                DigestMethod = _signingCredentials.Digest
            };

            var signedInfo = new SignedInfo(reference)
            {
                CanonicalizationMethod = SecurityAlgorithms.ExclusiveC14n,
                SignatureMethod = _signingCredentials.Algorithm
            };

            var canonicalSignedInfoStream = new MemoryStream();
            var signedInfoWriter = CreateTextWriter(Stream.Null);
            signedInfoWriter.StartCanonicalization(canonicalSignedInfoStream, false, XmlUtil.TokenizeInclusivePrefixList(_inclusivePrefixList));
            DSigSerializer.WriteSignedInfo(signedInfoWriter, signedInfo);
            signedInfoWriter.EndCanonicalization();
            signedInfoWriter.Flush();
            var provider = _signingCredentials.Key.CryptoProviderFactory.CreateForSigning(_signingCredentials.Key, signedInfo.SignatureMethod);
            return new Signature
            {
                KeyInfo = new KeyInfo(_signingCredentials.Key),
                SignatureValue = Convert.ToBase64String(provider.Sign(canonicalSignedInfoStream.ToArray())),
                SignedInfo = signedInfo,
            };
        }

        /// <summary>
        /// Sets the position of the signature within the envelope. Call this
        /// method while writing the envelope to indicate at which point the 
        /// signature should be inserted.
        /// </summary>
        public void WriteSignature()
        {
            InnerWriter.Flush();
            _signaturePosition = _writerStream.Length;
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

                if (_canonicalStream != null)
                {
                    _canonicalStream.Dispose();
                    _canonicalStream = null;
                }
            }
        }

#endregion
    }
}
