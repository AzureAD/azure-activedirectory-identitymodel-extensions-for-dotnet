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
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents the &lt;Reference> element in a &lt;SignedInfo> clause.
    /// </summary>
    public class Reference
    {
        private ElementWithAlgorithmAttribute _digestMethodElement = new ElementWithAlgorithmAttribute(XmlSignatureConstants.Elements.DigestMethod);
        private DigestValueElement _digestValueElement = new DigestValueElement();
        private string _prefix = XmlSignatureConstants.Prefix;

        public Reference()
        {
            TransformChain = new TransformChain();
        }

        public Reference(params Transform[] transforms)
        {
            if (transforms == null)
                LogArgumentNullException(nameof(transforms));

            TransformChain = new TransformChain(transforms);
        }

        public string DigestAlgorithm
        {
            get { return _digestMethodElement.Algorithm; }
            set { _digestMethodElement.Algorithm = value; }
        }

        public string  DigestText { get; set; }

        public byte[]  DigestBytes { get; set; }

        public string Id { get; set; }

        public TransformChain TransformChain { get; private set; } = new TransformChain();

        public string Type { get; set; }

        public string Uri { get; set; }

        public bool Verified { get; set; }

        internal bool Verify(CryptoProviderFactory cryptoProviderFactory, XmlTokenStreamReader tokenStream)
        {
            Verified = Utility.AreEqual(ComputeDigest(cryptoProviderFactory, tokenStream), DigestBytes);
            return Verified;
        }

        /// <summary>
        /// We look at the URI reference to decide if we should preserve comments while canonicalization.
        /// Only when the reference is xpointer(/) or xpointer(id(SomeId)) do we preserve comments during canonicalization 
        /// of the reference element for computing the digest.
        /// </summary>
        /// <param name="uri">The Uri reference </param>
        /// <returns>true if comments should be preserved.</returns>
        private static bool ShouldPreserveComments(string uri)
        {
            bool preserveComments = false;

            if (!string.IsNullOrEmpty(uri))
            {
                //removes the hash
                string idref = uri.Substring(1);

                if (idref == "xpointer(/)")
                {
                    preserveComments = true;
                }
                else if (idref.StartsWith("xpointer(id(", StringComparison.Ordinal) && (idref.IndexOf(")", StringComparison.Ordinal) > 0))
                {
                    // Dealing with XPointer of type #xpointer(id("ID")). Other XPointer support isn't handled here and is anyway optional 
                    preserveComments = true;
                }
            }

            return preserveComments;
        }

        // TODO - hook this up to write
        internal void ComputeAndSetDigest()
        {
            //_digestValueElement.Value = ComputeDigest();
        }

        //public byte[] ComputeDigest()
        //{
        //    if (TransformChain.TransformCount == 0)
        //        throw LogExceptionMessage(new NotSupportedException("EmptyTransformChainNotSupported"));

        //    if (_resolvedXmlSource == null)
        //        throw LogExceptionMessage(new CryptographicException("UnableToResolveReferenceUriForSignature, this.uri"));

        //    return TransformChain.TransformToDigest(_resolvedXmlSource, DigestAlgorithm);
        //}

        private byte[] ComputeDigest(CryptoProviderFactory providerFactory, XmlTokenStreamReader tokenStream)
        {
            if (tokenStream == null)
                throw LogArgumentNullException(nameof(tokenStream));

            if (TransformChain.Count == 0)
                throw LogExceptionMessage(new NotSupportedException("EmptyTransformChainNotSupported"));

            var hashAlg = providerFactory.CreateHashAlgorithm(DigestAlgorithm);
            try
            {
                return TransformChain.TransformToDigest(tokenStream, hashAlg);
            }
            finally
            {

                providerFactory.ReleaseHashAlgorithm(hashAlg);
            }
        }

        public void ReadFrom(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace);

            reader.MoveToStartElement(XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace);
            _prefix = reader.Prefix;
            Id = reader.GetAttribute(XmlSignatureConstants.Attributes.Id, null);
            Uri = reader.GetAttribute(XmlSignatureConstants.Attributes.URI, null);
            Type = reader.GetAttribute(XmlSignatureConstants.Attributes.Type, null);

            reader.Read();

            if (reader.IsStartElement(XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace))
                TransformChain.ReadFrom(reader, ShouldPreserveComments(Uri));
            else
                throw XmlUtil.LogReadException(LogMessages.IDX21011, XmlSignatureConstants.Namespace, XmlSignatureConstants.Elements.Transforms, reader.NamespaceURI, reader.LocalName);


            // <DigestMethod>
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Namespace);
            reader.MoveToStartElement(XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Namespace);
            bool isEmptyElement = reader.IsEmptyElement;
            DigestAlgorithm = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
            if (string.IsNullOrEmpty(DigestAlgorithm))
                throw XmlUtil.OnRequiredAttributeMissing(XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Attributes.Algorithm);

            reader.Read();
            reader.MoveToContent();
            if (!isEmptyElement)
            {
                reader.MoveToContent();
                reader.ReadEndElement();
            }

            // <DigestValue>
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.DigestValue, XmlSignatureConstants.Namespace);
            DigestText = reader.ReadElementContentAsString().Trim();
            DigestBytes = System.Convert.FromBase64String(DigestText);

            // </Reference>
            reader.MoveToContent();
            reader.ReadEndElement();
            reader.MoveToContent();
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(_prefix, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace);
            if (Id != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Id, null, Id);

            if (Uri != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.URI, null, Uri);

            if (Type != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Type, null, Type);

            if (TransformChain.Count > 0)
                TransformChain.WriteTo(writer);

            _digestMethodElement.WriteTo(writer);
            _digestValueElement.WriteTo(writer);

            writer.WriteEndElement();
        }

        struct DigestValueElement
        {
            byte[] _digestValue;
            string _digestText;

            internal byte[] Value
            {
                get { return _digestValue; }
                set
                {
                    _digestValue = value;
                    _digestText = null;
                }
            }

            public void WriteTo(XmlDictionaryWriter writer)
            {
                writer.WriteStartElement(XmlSignatureConstants.Prefix, XmlSignatureConstants.Elements.DigestValue, XmlSignatureConstants.Namespace);
                if (_digestText != null)
                    writer.WriteString(_digestText);
                else
                    writer.WriteBase64(_digestValue, 0, _digestValue.Length);

                writer.WriteEndElement();
            }
        }
    }
}