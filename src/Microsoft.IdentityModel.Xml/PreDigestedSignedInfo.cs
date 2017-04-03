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
    internal class PreDigestedSignedInfo : SignedInfo
    {
        private const int _initialReferenceArraySize = 8;
        private int _count;
        private ReferenceEntry[] _references;

        public PreDigestedSignedInfo()
        {
            _references = new ReferenceEntry[_initialReferenceArraySize];
        }

        public PreDigestedSignedInfo(
            string canonicalizationMethod,
            string digestMethod,
            string signatureMethod)
        {
            _references = new ReferenceEntry[_initialReferenceArraySize];
            CanonicalizationMethod = canonicalizationMethod;
            DigestMethod = digestMethod;
            SignatureMethod = signatureMethod;
        }

        public bool AddEnvelopedSignatureTransform { get; set; }

        public string DigestMethod { get; private set; }

        public override int ReferenceCount
        {
            get { return _count; }
        }

        public void AddReference(string id, byte[] digest)
        {
            AddReference(id, digest, false);
        }

        public void AddReference(string id, byte[] digest, bool useStrTransform)
        {
            if (_count == _references.Length)
            {
                ReferenceEntry[] newReferences = new ReferenceEntry[_references.Length * 2];
                Array.Copy(_references, 0, newReferences, 0, _count);
                _references = newReferences;
            }
            _references[_count++].Set(id, digest, useStrTransform);
        }

        public override void ComputeHash(HashStream hashStream)
        {
            GetCanonicalBytes(hashStream);
        }

        public override void GetCanonicalBytes(Stream stream)
        {
            if (AddEnvelopedSignatureTransform)
            {
                base.GetCanonicalBytes(stream);
            }
            else
            {
                SignedInfoCanonicalFormWriter.Instance.WriteSignedInfoCanonicalForm(
                    stream, SignatureMethod, DigestMethod,
                    _references, _count,
                    ResourcePool.TakeEncodingBuffer(), ResourcePool.TakeBase64Buffer());
            }
        }

        public override void ComputeReferenceDigests()
        {
            // all digests pre-computed
        }

        public override void ReadFrom(XmlDictionaryReader reader, TransformFactory transformFactory)
        {
            // WriteOnly
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        public override void EnsureAllReferencesVerified()
        {
            // WriteOnly
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        public override bool EnsureDigestValidityIfIdMatches(string id, object resolvedXmlSource)
        {
            // WriteOnly
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        public override void WriteTo(XmlDictionaryWriter writer)
        {
            string prefix = XmlSignatureConstants.Prefix;
            writer.WriteStartElement(prefix, XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Namespace);
            if (!string.IsNullOrEmpty(Id))
                writer.WriteAttributeString(UtilityStrings.Id, null, Id);
            WriteCanonicalizationMethod(writer);
            WriteSignatureMethod(writer);
            for (int i = 0; i < _count; i++)
            {
                writer.WriteStartElement(prefix, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace);
                writer.WriteStartAttribute(XmlSignatureConstants.Attributes.URI, null);
                writer.WriteString("#");
                writer.WriteString(_references[i]._id);
                writer.WriteEndAttribute();

                writer.WriteStartElement(prefix, XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace);
                if (AddEnvelopedSignatureTransform)
                {
                    writer.WriteStartElement(prefix, XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace);
                    writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                    writer.WriteString(XmlSignatureConstants.Algorithms.EnvelopedSignature);
                    writer.WriteEndAttribute();
                    writer.WriteEndElement(); // Transform
                }

                if (_references[i]._useStrTransform)
                {
                    writer.WriteStartElement(prefix, XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace);
                    writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                    writer.WriteString(SecurityAlgorithms.StrTransform);
                    writer.WriteEndAttribute();
                    writer.WriteStartElement(XmlSignatureConstants.SecurityJan2004Prefix, XmlSignatureConstants.TransformationParameters, XmlSignatureConstants.SecurityJan2004Namespace);  //<wsse:TransformationParameters>
                    writer.WriteStartElement(prefix, XmlSignatureConstants.Elements.CanonicalizationMethod, XmlSignatureConstants.Namespace);
                    writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                    writer.WriteString(XmlSignatureConstants.ExclusiveC14n);
                    writer.WriteEndAttribute();
                    writer.WriteEndElement(); //CanonicalizationMethod 
                    writer.WriteEndElement(); // TransformationParameters
                    writer.WriteEndElement(); // Transform
                }
                else
                {
                    writer.WriteStartElement(prefix, XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace);
                    writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                    writer.WriteString(XmlSignatureConstants.ExclusiveC14n);
                    writer.WriteEndAttribute();
                    writer.WriteEndElement(); // Transform
                }

                writer.WriteEndElement(); // Transforms

                writer.WriteStartElement(prefix, XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Namespace);
                writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                writer.WriteString(DigestMethod);
                writer.WriteEndAttribute();
                writer.WriteEndElement(); // DigestMethod

                byte[] digest = _references[i]._digest;
                writer.WriteStartElement(prefix, XmlSignatureConstants.Elements.DigestValue, XmlSignatureConstants.Namespace);
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
            internal bool _useStrTransform;

            public void Set(string id, byte[] digest, bool useStrTransform)
            {
                if (useStrTransform && string.IsNullOrEmpty(id))
                    throw LogHelper.LogExceptionMessage(new XmlSignedInfoException(id));

                _id = id;
                _digest = digest;
                _useStrTransform = useStrTransform;
            }
        }

        sealed class SignedInfoCanonicalFormWriter : CanonicalFormWriter
        {
            const string _xml1 = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod><SignatureMethod Algorithm=\"";
            const string _xml2 = "\"></SignatureMethod>";
            const string _xml3 = "<Reference URI=\"#";
            const string _xml4 = "\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"";
            const string _xml4WithStrTransform = "\"><Transforms><Transform Algorithm=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform\"><o:TransformationParameters xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod></o:TransformationParameters></Transform></Transforms><DigestMethod Algorithm=\"";
            const string _xml5 = "\"></DigestMethod><DigestValue>";
            const string _xml6 = "</DigestValue></Reference>";
            const string _xml7 = "</SignedInfo>";

            readonly byte[] _fragment1;
            readonly byte[] _fragment2;
            readonly byte[] _fragment3;
            readonly byte[] _fragment4;
            readonly byte[] _fragment4StrTransform;
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
                _fragment4StrTransform = encoding.GetBytes(_xml4WithStrTransform);
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
                ReferenceEntry[] references, int referenceCount,
                byte[] workBuffer, char[] base64WorkBuffer)
            {
                stream.Write(_fragment1, 0, _fragment1.Length);
                byte[] signatureMethodBytes = EncodeSignatureAlgorithm(signatureMethod);
                stream.Write(signatureMethodBytes, 0, signatureMethodBytes.Length);
                stream.Write(_fragment2, 0, _fragment2.Length);

                byte[] digestMethodBytes = EncodeDigestAlgorithm(digestMethod);
                for (int i = 0; i < referenceCount; i++)
                {
                    stream.Write(_fragment3, 0, _fragment3.Length);
                    EncodeAndWrite(stream, workBuffer, references[i]._id);
                    if (references[i]._useStrTransform)
                        stream.Write(_fragment4StrTransform, 0, _fragment4StrTransform.Length);
                    else
                        stream.Write(_fragment4, 0, _fragment4.Length);

                    stream.Write(digestMethodBytes, 0, digestMethodBytes.Length);
                    stream.Write(_fragment5, 0, _fragment5.Length);
                    Base64EncodeAndWrite(stream, workBuffer, base64WorkBuffer, references[i]._digest);
                    stream.Write(_fragment6, 0, _fragment6.Length);
                }

                stream.Write(_fragment7, 0, _fragment7.Length);
            }
        }
    }
}
