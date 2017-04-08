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
    /// Represents the &lt;Reference> element in a &lt;SignedInfo> clause.
    /// </summary>
    public class Reference
    {
        private ElementWithAlgorithmAttribute _digestMethodElement;
        private DigestValueElement _digestValueElement = new DigestValueElement();
        private string _prefix = XmlSignatureConstants.Prefix;
        private string _referredId;
        private object _resolvedXmlSource;
        private readonly TransformChain _transformChain = new TransformChain();
        private bool _verified;

        public Reference()
            : this(null)
        { }

        public Reference(string uri)
            : this(uri, null)
        { }

        public Reference(string uri, object resolvedXmlSource)
        {
            _digestMethodElement = new ElementWithAlgorithmAttribute(XmlSignatureConstants.Elements.DigestMethod);
            Uri = uri;
            _resolvedXmlSource = resolvedXmlSource;
        }

        public string DigestAlgorithm
        {
            get { return _digestMethodElement.Algorithm; }
            set { _digestMethodElement.Algorithm = value; }
        }

        public string Id { get; set; }

        public SignatureResourcePool ResourcePool { get; set; }

        public TransformChain TransformChain
        {
            get { return _transformChain; }
        }

        public int TransformCount
        {
            get { return _transformChain.TransformCount; }
        }

        public string Type { get; set; }

        public string Uri { get; set; }

        public bool Verified
        {
            get { return _verified; }
        }

        public void AddTransform(Transform transform)
        {
            _transformChain.Add(transform);
        }

        public void EnsureDigestValidity(string id, byte[] computedDigest)
        {
            if (!EnsureDigestValidityIfIdMatches(id, computedDigest))
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("RequiredTargetNotSigned, id"));
            }
        }

        public void EnsureDigestValidity(string id, object resolvedXmlSource)
        {
            if (!EnsureDigestValidityIfIdMatches(id, resolvedXmlSource))
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("RequiredTargetNotSigned, id"));
            }
        }

        public bool EnsureDigestValidityIfIdMatches(string id, byte[] computedDigest)
        {
            if (_verified || id != ExtractReferredId())
                return true;

            if (!Utility.AreEqual(computedDigest, GetDigestValue()))
                throw LogHelper.LogExceptionMessage(new CryptographicException($"DigestVerificationFailedForReference: id: {id}"));

            _verified = true;
            return true;
        }

        public bool EnsureDigestValidityIfIdMatches(string id, object resolvedXmlSource)
        {
            if (_verified)
                return true;

            // During StrTransform the extractedReferredId on the reference will point to STR and hence will not be 
            // equal to the referred element ie security token Id.
            if (id != ExtractReferredId() && !IsStrTranform())
                return false;

            _resolvedXmlSource = resolvedXmlSource;
            if (!CheckDigest())
                throw LogHelper.LogExceptionMessage(new CryptographicException($"DigestVerificationFailedForReference: id: {id}"));

            _verified = true;
            return true;
        }

        public bool IsStrTranform()
        {
            return TransformChain.TransformCount == 1 && TransformChain[0].Algorithm == SecurityAlgorithms.StrTransform;
        }


        public string ExtractReferredId()
        {
            if (_referredId == null)
            {
                if (StringComparer.OrdinalIgnoreCase.Equals(Uri, String.Empty))
                {
                    return String.Empty;
                }

                if (Uri == null || Uri.Length < 2 || Uri[0] != '#')
                    throw LogHelper.LogExceptionMessage(new XmlSignedInfoException("UnableToResolveReferenceUriForSignature, this.uri"));

                _referredId = Uri.Substring(1);
            }

            return _referredId;
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

        public bool CheckDigest()
        {
            byte[] computedDigest = ComputeDigest();
            bool result = Utility.AreEqual(computedDigest, GetDigestValue());
#if LOG_DIGESTS
            Console.WriteLine(">>> Checking digest for reference '{0}', result {1}", uri, result);
            Console.WriteLine("    Computed digest {0}", Convert.ToBase64String(computedDigest));
            Console.WriteLine("    Received digest {0}", Convert.ToBase64String(GetDigestValue()));
#endif
            return result;
        }

        public void ComputeAndSetDigest()
        {
            _digestValueElement.Value = ComputeDigest();
        }

        public byte[] ComputeDigest()
        {
            if (_transformChain.TransformCount == 0)
                throw LogHelper.LogExceptionMessage(new NotSupportedException("EmptyTransformChainNotSupported"));

            if (_resolvedXmlSource == null)
                throw LogHelper.LogExceptionMessage(new CryptographicException("UnableToResolveReferenceUriForSignature, this.uri"));

            return _transformChain.TransformToDigest(_resolvedXmlSource, ResourcePool, DigestAlgorithm);
        }

        public byte[] GetDigestValue()
        {
            return _digestValueElement.Value;
        }

        public void ReadFrom(XmlDictionaryReader reader, TransformFactory transformFactory)
        {
            if (reader == null)
                LogHelper.LogArgumentNullException(nameof(reader));

            reader.MoveToStartElement(XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace);
            _prefix = reader.Prefix;
            Id = reader.GetAttribute(UtilityStrings.Id, null);
            Uri = reader.GetAttribute(XmlSignatureConstants.Attributes.URI, null);
            Type = reader.GetAttribute(XmlSignatureConstants.Attributes.Type, null);
            reader.Read();

            if (reader.IsStartElement(XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace))
                _transformChain.ReadFrom(reader, transformFactory, ShouldPreserveComments(Uri));

            _digestMethodElement.ReadFrom(reader);
            _digestValueElement.ReadFrom(reader);

            reader.MoveToContent();
            reader.ReadEndElement(); // Reference
        }

        public void SetResolvedXmlSource(object resolvedXmlSource)
        {
            _resolvedXmlSource = resolvedXmlSource;
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(_prefix, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace);
            if (Id != null)
                writer.WriteAttributeString(UtilityStrings.Id, null, Id);

            if (Uri != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.URI, null, Uri);

            if (Type != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Type, null, Type);

            if (_transformChain.TransformCount > 0)
                _transformChain.WriteTo(writer);

            _digestMethodElement.WriteTo(writer);
            _digestValueElement.WriteTo(writer);

            writer.WriteEndElement(); // Reference
        }

        struct DigestValueElement
        {
            byte[] _digestValue;
            string _digestText;
            string _prefix;

            internal byte[] Value
            {
                get { return _digestValue; }
                set
                {
                    _digestValue = value;
                    _digestText = null;
                }
            }

            public void ReadFrom(XmlDictionaryReader reader)
            {
                reader.MoveToStartElement(XmlSignatureConstants.Elements.DigestValue, XmlSignatureConstants.Namespace);
                _prefix = reader.Prefix;
                reader.Read();
                reader.MoveToContent();

                _digestText = reader.ReadString();
                _digestValue = System.Convert.FromBase64String(_digestText.Trim());

                reader.MoveToContent();
                reader.ReadEndElement(); // DigestValue
            }

            public void WriteTo(XmlDictionaryWriter writer)
            {
                writer.WriteStartElement(_prefix ?? XmlSignatureConstants.Prefix, XmlSignatureConstants.Elements.DigestValue, XmlSignatureConstants.Namespace);
                if (_digestText != null)
                    writer.WriteString(_digestText);
                else
                    writer.WriteBase64(_digestValue, 0, _digestValue.Length);

                writer.WriteEndElement(); // DigestValue
            }
        }
    }
}