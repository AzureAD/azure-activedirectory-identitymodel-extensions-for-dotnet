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
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Wraps a writer and generates a signature automatically when the envelope
    /// is written completely. By default the generated signature is inserted as
    /// the last element in the envelope. This can be modified by explicitily 
    /// calling WriteSignature to indicate the location inside the envelope where
    /// the signature should be inserted.
    /// </summary>
    public sealed class EnvelopedSignatureWriter : DelegatingXmlDictionaryWriter
    {
        private bool _disposed;
        private int _elementCount;
        private MemoryStream _endFragment;
        private HashAlgorithm _hashAlgorithm;
        private HashStream _hashStream;
        private bool _hasSignatureBeenMarkedForInsert;
        private XmlWriter _innerWriter;
        private MemoryStream _preCanonicalTracingStream;
        private string _referenceId;
        private MemoryStream _signatureFragment;
        private SigningCredentials _signingCredentials;
        private MemoryStream _writerStream;

        /// <summary>
        /// Initializes an instance of <see cref="EnvelopedSignatureWriter"/>. The returned writer can be directly used
        /// to write the envelope. The signature will be automatically generated when 
        /// the envelope is completed.
        /// </summary>
        /// <param name="innerWriter">Writer to wrap/</param>
        /// <param name="signingCredentials">SigningCredentials to be used to generate the signature.</param>
        /// <param name="referenceId">The reference Id of the envelope.</param>
        /// <param name="securityTokenSerializer">SecurityTokenSerializer to serialize the signature KeyInfo.</param>
        /// <exception cref="ArgumentNullException">One of he input parameters is null.</exception>
        /// <exception cref="ArgumentNullException">The parameter 'referenceId' is empty.</exception>
        public EnvelopedSignatureWriter(XmlWriter innerWriter, SigningCredentials signingCredentials, string referenceId)
        {
            if (innerWriter == null)
                throw LogHelper.LogArgumentNullException(nameof(innerWriter));

            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            if (string.IsNullOrEmpty(referenceId))
                throw LogHelper.LogArgumentNullException(nameof(referenceId));

            // the Signature will be written into the innerWriter.
            _innerWriter = innerWriter;
            _signingCredentials = signingCredentials;
            _referenceId = referenceId;
            _endFragment = new MemoryStream();
            _signatureFragment = new MemoryStream();
            _writerStream = new MemoryStream();

            var effectiveWriter = XmlDictionaryWriter.CreateTextWriter(_writerStream, Encoding.UTF8, false);
            SetCanonicalizingWriter(effectiveWriter);
            // TODO - create when needed
            _hashAlgorithm = _signingCredentials.Key.CryptoProviderFactory.CreateHashAlgorithm(signingCredentials.Digest);
            _hashStream = new HashStream(_hashAlgorithm);
            // TODO - why exclude comments?
            InnerWriter.StartCanonicalization(_hashStream, false, null);
        }

        private void ComputeSignature()
        {
            var signedInfo = new PreDigestedSignedInfo(XmlSignatureConstants.Algorithms.ExcC14N,_signingCredentials.Digest, _signingCredentials.Algorithm) { SendSide = true };
            signedInfo.AddReference(_referenceId, _hashStream.FlushHashAndGetValue(_preCanonicalTracingStream));

            var signature = new Signature(signedInfo);
            signature.WriteTo(base.InnerWriter, _signingCredentials);
            ((IDisposable)_hashStream).Dispose();
            _hashStream = null;
        }

        private void OnEndRootElement()
        {
            if (!_hasSignatureBeenMarkedForInsert)
            {
                // Default case. Signature is added as the last child element.
                // We still have to compute the signature. Write end element as a different fragment.

                ((IFragmentCapableXmlDictionaryWriter)base.InnerWriter).StartFragment(_endFragment, false);
                base.WriteEndElement();
                ((IFragmentCapableXmlDictionaryWriter)base.InnerWriter).EndFragment();
            }
            else if (_hasSignatureBeenMarkedForInsert)
            {
                // Signature should be added to the middle between the start and element 
                // elements. Finish the end fragment and compute the signature and 
                // write the signature as a seperate fragment.
                base.WriteEndElement();
                ((IFragmentCapableXmlDictionaryWriter)base.InnerWriter).EndFragment();
            }

            // Stop Canonicalization.
            base.EndCanonicalization();

            // Compute signature and write it into a seperate fragment.
            ((IFragmentCapableXmlDictionaryWriter)base.InnerWriter).StartFragment(_signatureFragment, false);
            ComputeSignature();
            ((IFragmentCapableXmlDictionaryWriter)base.InnerWriter).EndFragment();

            // Put all fragments together. The fragment before the signature is already written into the writer.
            ((IFragmentCapableXmlDictionaryWriter)base.InnerWriter).WriteFragment(_signatureFragment.GetBuffer(), 0, (int)_signatureFragment.Length);
            ((IFragmentCapableXmlDictionaryWriter)base.InnerWriter).WriteFragment(_endFragment.GetBuffer(), 0, (int)_endFragment.Length);

            // _startFragment.Close();
            _signatureFragment.Close();
            _endFragment.Close();

            _writerStream.Position = 0;
            _hasSignatureBeenMarkedForInsert = false;

            // Write the signed stream to the writer provided by the user.
            // We are creating a Text Reader over a stream that we just wrote out. Hence, it is safe to 
            // create a XmlTextReader and not a XmlDictionaryReader.
            // Note: reader will close _writerStream on Dispose.
            XmlReader reader = XmlDictionaryReader.CreateTextReader(_writerStream, XmlDictionaryReaderQuotas.Max);
            reader.MoveToContent();
            _innerWriter.WriteNode(reader, false);
            _innerWriter.Flush();
            reader.Close();
            base.Close();
        }

        /// <summary>
        /// Sets the position of the signature within the envelope. Call this
        /// method while writing the envelope to indicate at which point the 
        /// signature should be inserted.
        /// </summary>
        public void WriteSignature()
        {
            base.Flush();
            if (_writerStream == null || _writerStream.Length == 0)
                LogHelper.LogExceptionMessage(new InvalidOperationException("ID6029"));

            if (_signatureFragment.Length != 0)
                LogHelper.LogExceptionMessage(new InvalidOperationException("ID6030"));

            // Capture the remaing as a seperate fragment.
            ((IFragmentCapableXmlDictionaryWriter)base.InnerWriter).StartFragment(_endFragment, false);

            _hasSignatureBeenMarkedForInsert = true;
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
        /// <param name="ns">The namespace URI to associate with the element.</param>
        public override void WriteStartElement(string prefix, string localName, string ns)
        {
            _elementCount++;
            base.WriteStartElement(prefix, localName, ns);
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

            if (disposing)
            {
                //
                // Free all of our managed resources
                //
                if (_hashStream != null)
                {
                    _hashStream.Dispose();
                    _hashStream = null;
                }

                if (_hashAlgorithm != null)
                {
                    ((IDisposable)_hashAlgorithm).Dispose();
                    _hashAlgorithm = null;
                }

                if (_signatureFragment != null)
                {
                    _signatureFragment.Dispose();
                    _signatureFragment = null;
                }

                if (_endFragment != null)
                {
                    _endFragment.Dispose();
                    _endFragment = null;
                }

                if (_writerStream != null)
                {
                    _writerStream.Dispose();
                    _writerStream = null;
                }

                if (_preCanonicalTracingStream != null)
                {
                    _preCanonicalTracingStream.Dispose();
                    _preCanonicalTracingStream = null;
                }
            }

            // Free native resources, if any.

            _disposed = true;
        }

        #endregion
    }
}
