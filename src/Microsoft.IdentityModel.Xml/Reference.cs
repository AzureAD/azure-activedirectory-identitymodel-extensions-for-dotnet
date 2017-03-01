//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    public class Reference
    {
        ElementWithAlgorithmAttribute digestMethodElement;
        DigestValueElement digestValueElement = new DigestValueElement();
        string id;
        string prefix = SignedXml.DefaultPrefix;
        object resolvedXmlSource;
        readonly TransformChain transformChain = new TransformChain();
        string type;
        string uri;
        SignatureResourcePool resourcePool;
        bool verified;
        string referredId;

        public Reference()
            : this(null)
        {
        }

        public Reference(string uri)
            : this(uri, null)
        {
        }

        public Reference(string uri, object resolvedXmlSource)
        {
            this.digestMethodElement = new ElementWithAlgorithmAttribute(XmlSignatureStrings.DigestMethod);
            this.uri = uri;
            this.resolvedXmlSource = resolvedXmlSource;
        }

        public string DigestMethod
        {
            get { return this.digestMethodElement.Algorithm; }
            set { this.digestMethodElement.Algorithm = value; }
        }

        public string Id
        {
            get { return this.id; }
            set { this.id = value; }
        }

        public SignatureResourcePool ResourcePool
        {
            get { return this.resourcePool; }
            set { this.resourcePool = value; }
        }

        public TransformChain TransformChain
        {
            get { return this.transformChain; }
        }

        public int TransformCount
        {
            get { return this.transformChain.TransformCount; }
        }

        public string Type
        {
            get { return this.type; }
            set { this.type = value; }
        }

        public string Uri
        {
            get { return this.uri; }
            set { this.uri = value; }
        }

        public bool Verified
        {
            get { return this.verified; }
        }

        public void AddTransform(Transform transform)
        {
            this.transformChain.Add(transform);
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
            if (this.verified || id != ExtractReferredId())
            {
                return false;
            }
            if (!Utility.AreEqual(computedDigest, GetDigestValue()))
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("DigestVerificationFailedForReference, this.uri"));
            }
            this.verified = true;
            return true;
        }

        public bool EnsureDigestValidityIfIdMatches(string id, object resolvedXmlSource)
        {
            if (this.verified)
            {
                return false;
            }

            // During StrTransform the extractedReferredId on the reference will point to STR and hence will not be 
            // equal to the referred element ie security token Id.
            if (id != ExtractReferredId() && !this.IsStrTranform())
            {
                return false;
            }

            this.resolvedXmlSource = resolvedXmlSource;
            if (!CheckDigest())
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("DigestVerificationFailedForReference, this.uri"));
            }
            this.verified = true;
            return true;
        }

        public bool IsStrTranform()
        {
            return this.TransformChain.TransformCount == 1 && this.TransformChain[0].Algorithm == SecurityAlgorithms.StrTransform;
        }


        public string ExtractReferredId()
        {
            if (this.referredId == null)
            {
                if (StringComparer.OrdinalIgnoreCase.Equals(uri, String.Empty))
                {
                    return String.Empty;
                }

                if (this.uri == null || this.uri.Length < 2 || this.uri[0] != '#')
                {
                    throw LogHelper.LogExceptionMessage(new CryptographicException("UnableToResolveReferenceUriForSignature, this.uri"));
                }
                this.referredId = this.uri.Substring(1);
            }
            return this.referredId;
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

            if (!String.IsNullOrEmpty(uri))
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
            this.digestValueElement.Value = ComputeDigest();
        }

        public byte[] ComputeDigest()
        {
            if (this.transformChain.TransformCount == 0)
            {
                throw LogHelper.LogExceptionMessage(new NotSupportedException("EmptyTransformChainNotSupported"));
            }

            if (this.resolvedXmlSource == null)
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("UnableToResolveReferenceUriForSignature, this.uri"));
            }
            return this.transformChain.TransformToDigest(this.resolvedXmlSource, this.ResourcePool, this.DigestMethod);
        }

        public byte[] GetDigestValue()
        {
            return this.digestValueElement.Value;
        }

        public void ReadFrom(XmlDictionaryReader reader, TransformFactory transformFactory)
        {
            reader.MoveToStartElement(XmlSignatureStrings.Reference, XmlSignatureStrings.Namespace);
            this.prefix = reader.Prefix;
            this.Id = reader.GetAttribute(UtilityStrings.Id, null);
            this.Uri = reader.GetAttribute(XmlSignatureStrings.URI, null);
            this.Type = reader.GetAttribute(XmlSignatureStrings.Type, null);
            reader.Read();

            if (reader.IsStartElement(XmlSignatureStrings.Transforms, XmlSignatureStrings.Namespace))
            {
                this.transformChain.ReadFrom(reader, transformFactory, ShouldPreserveComments(this.Uri));
            }

            this.digestMethodElement.ReadFrom(reader);
            this.digestValueElement.ReadFrom(reader);

            reader.MoveToContent();
            reader.ReadEndElement(); // Reference
        }

        public void SetResolvedXmlSource(object resolvedXmlSource)
        {
            this.resolvedXmlSource = resolvedXmlSource;
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(this.prefix, XmlSignatureStrings.Reference, XmlSignatureStrings.Namespace);
            if (this.id != null)
            {
                writer.WriteAttributeString(UtilityStrings.Id, null, this.id);
            }
            if (this.uri != null)
            {
                writer.WriteAttributeString(XmlSignatureStrings.URI, null, this.uri);
            }
            if (this.type != null)
            {
                writer.WriteAttributeString(XmlSignatureStrings.Type, null, this.type);
            }

            if (this.transformChain.TransformCount > 0)
            {
                this.transformChain.WriteTo(writer);
            }

            this.digestMethodElement.WriteTo(writer);
            this.digestValueElement.WriteTo(writer);

            writer.WriteEndElement(); // Reference
        }

        struct DigestValueElement
        {
            byte[] digestValue;
            string digestText;
            string prefix;

            internal byte[] Value
            {
                get { return this.digestValue; }
                set
                {
                    this.digestValue = value;
                    this.digestText = null;
                }
            }

            public void ReadFrom(XmlDictionaryReader reader)
            {
                reader.MoveToStartElement(XmlSignatureStrings.DigestValue, XmlSignatureStrings.Namespace);
                this.prefix = reader.Prefix;
                reader.Read();
                reader.MoveToContent();

                this.digestText = reader.ReadString();
                this.digestValue = System.Convert.FromBase64String(digestText.Trim());

                reader.MoveToContent();
                reader.ReadEndElement(); // DigestValue
            }

            public void WriteTo(XmlDictionaryWriter writer)
            {
                writer.WriteStartElement(this.prefix ?? XmlSignatureStrings.Prefix, XmlSignatureStrings.DigestValue, XmlSignatureStrings.Namespace);
                if (this.digestText != null)
                {
                    writer.WriteString(this.digestText);
                }
                else
                {
                    writer.WriteBase64(this.digestValue, 0, this.digestValue.Length);
                }
                writer.WriteEndElement(); // DigestValue
            }
        }
    }
}