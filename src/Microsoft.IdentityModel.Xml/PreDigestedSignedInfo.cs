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
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Essentially a performance enhancement used when writing signed info.
    /// Common elements have their hashes pre-calculated.
    /// Only used for writting
    /// </summary>
    internal class PreDigestedSignedInfo : SignedInfo
    {
        private ReferenceEntry _referenceEntry;

        public PreDigestedSignedInfo(
            string canonicalizationMethod,
            string digestMethod,
            string signatureAlgorithm)
        {
            if (string.IsNullOrEmpty(canonicalizationMethod))
                throw LogHelper.LogArgumentNullException(nameof(canonicalizationMethod));

            if (string.IsNullOrEmpty(digestMethod))
                throw LogHelper.LogArgumentNullException(nameof(digestMethod));

            if (string.IsNullOrEmpty(signatureAlgorithm))
                throw LogHelper.LogArgumentNullException(nameof(signatureAlgorithm));

            CanonicalizationMethod = canonicalizationMethod;
            DigestMethod = digestMethod;
            SignatureAlgorithm = signatureAlgorithm;
            SendSide = true;
        }

        public bool AddEnvelopedSignatureTransform { get; private set; } = true;

        public string DigestMethod { get; private set; }

        public void AddReference(string id, byte[] digest)
        {
            _referenceEntry = new ReferenceEntry();
            _referenceEntry.Set(id, digest);
        }

        internal override void ComputeHash(HashStream hashStream, SignatureResourcePool resourcePool)
        {
            GetCanonicalBytes(hashStream, resourcePool);
        }

        internal override void GetCanonicalBytes(Stream stream, SignatureResourcePool resourcePool)
        {
            if (AddEnvelopedSignatureTransform)
            {
                base.GetCanonicalBytes(stream, resourcePool);
            }
            else
            {
                SignedInfoCanonicalFormWriter.Instance.WriteSignedInfoCanonicalForm(
                    stream, SignatureAlgorithm, DigestMethod,
                    _referenceEntry, resourcePool.TakeEncodingBuffer(), resourcePool.TakeBase64Buffer());
            }
        }

        internal override void ComputeReferenceDigests(SignatureResourcePool resourcePool)
        {
            // all digests pre-computed
        }

        public override void ReadFrom(XmlDictionaryReader reader)
        {
            // WriteOnly
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        internal override void EnsureReferenceVerified()

        {
            // WriteOnly
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        //public override bool EnsureDigestValidityIfIdMatches(string id, object resolvedXmlSource)
        //{
        //    // WriteOnly
        //    throw LogHelper.LogExceptionMessage(new NotSupportedException());
        //}

        public override void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(Prefix, XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Namespace);
            if (!string.IsNullOrEmpty(Id))
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Id, null, Id);
            WriteCanonicalizationMethod(writer);
            WriteSignatureMethod(writer);
            if (_referenceEntry._digest != null)
            {
                writer.WriteStartElement(Prefix, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace);
                writer.WriteStartAttribute(XmlSignatureConstants.Attributes.URI, null);
                writer.WriteString("#");
                writer.WriteString(_referenceEntry._id);
                writer.WriteEndAttribute();

                writer.WriteStartElement(Prefix, XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace);
                if (AddEnvelopedSignatureTransform)
                {
                    writer.WriteStartElement(Prefix, XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace);
                    writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                    writer.WriteString(XmlSignatureConstants.Algorithms.EnvelopedSignature);
                    writer.WriteEndAttribute();
                    writer.WriteEndElement(); // Transform
                }

                writer.WriteStartElement(Prefix, XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace);
                writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                writer.WriteString(XmlSignatureConstants.ExclusiveC14n);
                writer.WriteEndAttribute();
                writer.WriteEndElement(); // Transform

                writer.WriteEndElement(); // Transforms

                writer.WriteStartElement(Prefix, XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Namespace);
                writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                writer.WriteString(DigestMethod);
                writer.WriteEndAttribute();
                writer.WriteEndElement(); // DigestMethod

                byte[] digest = _referenceEntry._digest;
                writer.WriteStartElement(Prefix, XmlSignatureConstants.Elements.DigestValue, XmlSignatureConstants.Namespace);
                writer.WriteBase64(digest, 0, digest.Length);
                writer.WriteEndElement(); // DigestValue

                writer.WriteEndElement(); // Reference
            }
            writer.WriteEndElement(); // SignedInfo
        }

        struct ReferenceEntry
        {
            internal string _id;
            internal byte[] _digest;

            public void Set(string id, byte[] digest)
            {
                _id = id;
                _digest = digest;
            }
        }

        sealed class SignedInfoCanonicalFormWriter : CanonicalFormWriter
        {
            const string _xml1 = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod><SignatureMethod Algorithm=\"";
            const string _xml2 = "\"></SignatureMethod>";
            const string _xml3 = "<Reference URI=\"#";
            const string _xml4 = "\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"";
            const string _xml5 = "\"></DigestMethod><DigestValue>";
            const string _xml6 = "</DigestValue></Reference>";
            const string _xml7 = "</SignedInfo>";

            readonly byte[] _fragment1;
            readonly byte[] _fragment2;
            readonly byte[] _fragment3;
            readonly byte[] _fragment4;
            readonly byte[] _fragment5;
            readonly byte[] _fragment6;
            readonly byte[] _fragment7;
            readonly byte[] _sha256Digest;
            readonly byte[] _hmacSha2Signature;
            readonly byte[] _rsaSha2Signature;

            static readonly SignedInfoCanonicalFormWriter _instance = new SignedInfoCanonicalFormWriter();

            SignedInfoCanonicalFormWriter()
            {
                var encoding = Utf8WithoutPreamble;
                _fragment1 = encoding.GetBytes(_xml1);
                _fragment2 = encoding.GetBytes(_xml2);
                _fragment3 = encoding.GetBytes(_xml3);
                _fragment4 = encoding.GetBytes(_xml4);
                _fragment5 = encoding.GetBytes(_xml5);
                _fragment6 = encoding.GetBytes(_xml6);
                _fragment7 = encoding.GetBytes(_xml7);
                _sha256Digest = encoding.GetBytes(SecurityAlgorithms.Sha256Digest);
                _hmacSha2Signature = encoding.GetBytes(SecurityAlgorithms.HmacSha256Signature);
                _rsaSha2Signature = encoding.GetBytes(SecurityAlgorithms.RsaSha256Signature);
            }

            public static SignedInfoCanonicalFormWriter Instance
            {
                get { return _instance; }
            }

            // optimization 
            byte[] EncodeDigestAlgorithm(string algorithm)
            {
                if (algorithm == SecurityAlgorithms.Sha256Digest)
                    return _sha256Digest;
                else
                    return Utf8WithoutPreamble.GetBytes(algorithm);
            }

            byte[] EncodeSignatureAlgorithm(string algorithm)
            {
                if (algorithm == SecurityAlgorithms.HmacSha256Signature)
                    return _hmacSha2Signature;
                else if (algorithm == SecurityAlgorithms.RsaSha256Signature)
                    return _rsaSha2Signature;
                else
                    return Utf8WithoutPreamble.GetBytes(algorithm);
            }

            public void WriteSignedInfoCanonicalForm(
                Stream stream, string signatureMethod, string digestMethod,
                ReferenceEntry reference, byte[] workBuffer, char[] base64WorkBuffer)
            {
                stream.Write(_fragment1, 0, _fragment1.Length);
                byte[] signatureMethodBytes = EncodeSignatureAlgorithm(signatureMethod);
                stream.Write(signatureMethodBytes, 0, signatureMethodBytes.Length);
                stream.Write(_fragment2, 0, _fragment2.Length);

                byte[] digestMethodBytes = EncodeDigestAlgorithm(digestMethod);
                stream.Write(_fragment3, 0, _fragment3.Length);
                EncodeAndWrite(stream, workBuffer, reference._id);
                stream.Write(_fragment4, 0, _fragment4.Length);
                stream.Write(digestMethodBytes, 0, digestMethodBytes.Length);
                stream.Write(_fragment5, 0, _fragment5.Length);
                Base64EncodeAndWrite(stream, workBuffer, base64WorkBuffer, reference._digest);
                stream.Write(_fragment6, 0, _fragment6.Length);
                stream.Write(_fragment7, 0, _fragment7.Length);
            }
        }
    }
}
