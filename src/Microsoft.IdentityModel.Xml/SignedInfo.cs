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
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    public class SignedInfo : ISecurityElement
    {
        readonly ExclusiveCanonicalizationTransform _canonicalizationMethodElement = new ExclusiveCanonicalizationTransform(true);
        ElementWithAlgorithmAttribute _signatureMethodElement;
        SignatureResourcePool _resourcePool;
        List<Reference> _references;

        public SignedInfo()
        {
            _signatureMethodElement = new ElementWithAlgorithmAttribute(XmlSignatureStrings.SignatureMethod);
            _references = new List<Reference>();
            Prefix = SignedXml.DefaultPrefix;
        }

        public MemoryStream CanonicalStream { get; set; }

        public bool SendSide { get; set; }

        public void AddReference(Reference reference)
        {
            reference.ResourcePool = ResourcePool;
            _references.Add(reference);
        }

        public ISignatureReaderProvider ReaderProvider { get; set; }

        public object SignatureReaderProviderCallbackContext { get; set; }

        public string CanonicalizationMethod
        {
            get { return _canonicalizationMethodElement.Algorithm; }
            set
            {
                if (value != _canonicalizationMethodElement.Algorithm)
                {
                    throw LogHelper.LogExceptionMessage(new NotSupportedException("UnsupportedTransformAlgorithm"));
                }
            }
        }

        public XmlDictionaryString CanonicalizationMethodDictionaryString
        {
            set
            {
                if (value != null && value.Value != _canonicalizationMethodElement.Algorithm)
                    throw LogHelper.LogExceptionMessage(new NotSupportedException("UnsupportedTransformAlgorithm"));
            }
        }

        public bool HasId
        {
            get { return true; }
        }

        public string Id { get; set; }

        public virtual int ReferenceCount
        {
            get { return _references.Count; }
        }

        public Reference this[int index]
        {
            get { return _references[index]; }
        }

        public string SignatureMethod { get; set; }

        public string SignatureMethodDictionaryString { get; set; }

        public SignatureResourcePool ResourcePool
        {
            get
            {
                if (_resourcePool == null)
                    _resourcePool = new SignatureResourcePool();

                return _resourcePool;
            }
            set
            {
                _resourcePool = value;
            }
        }

        public void ComputeHash(HashAlgorithm algorithm)
        {
            if ((CanonicalizationMethod != SecurityAlgorithms.ExclusiveC14n) && (CanonicalizationMethod != SecurityAlgorithms.ExclusiveC14nWithComments))
                throw LogHelper.LogExceptionMessage(new CryptographicException("UnsupportedTransformAlgorithm"));

            var hashStream = ResourcePool.TakeHashStream(algorithm);
            ComputeHash(hashStream);
            hashStream.FlushHash();
        }

        public virtual void ComputeHash(HashStream hashStream)
        {
            GetCanonicalBytes(hashStream);
        }

        public virtual void GetCanonicalBytes(Stream stream)
        {
            if (SendSide)
            {
                var utf8Writer = ResourcePool.TakeUtf8Writer();
                utf8Writer.StartCanonicalization(stream, false, null);
                WriteTo(utf8Writer);
                utf8Writer.EndCanonicalization();
            }
            else if (CanonicalStream != null)
            {
                CanonicalStream.WriteTo(stream);
            }
            else
            {
                if (ReaderProvider == null)
                    throw LogHelper.LogExceptionMessage(new XmlSignedInfoException("ReaderProvider == null"));

                var signatureReader = ReaderProvider.GetReader(SignatureReaderProviderCallbackContext);
                if (!signatureReader.CanCanonicalize)
                {
                    var ms = new MemoryStream();
                    var bufferingWriter = XmlDictionaryWriter.CreateBinaryWriter(ms);
                    string[] inclusivePrefix = GetInclusivePrefixes();
                    if (inclusivePrefix != null)
                    {
                        bufferingWriter.WriteStartElement("a");
                        for (int i = 0; i < inclusivePrefix.Length; ++i)
                        {
                            string ns = GetNamespaceForInclusivePrefix(inclusivePrefix[i]);
                            if (ns != null)
                            {
                                bufferingWriter.WriteXmlnsAttribute(inclusivePrefix[i], ns);
                            }
                        }
                    }
                    signatureReader.MoveToContent();
                    bufferingWriter.WriteNode(signatureReader, false);
                    if (inclusivePrefix != null)
                        bufferingWriter.WriteEndElement();
                    bufferingWriter.Flush();
                    byte[] buffer = ms.ToArray();
                    int bufferLength = (int)ms.Length;
                    bufferingWriter.Close();

                    signatureReader.Close();

                    // Create a reader around the buffering Stream.
                    signatureReader = XmlDictionaryReader.CreateBinaryReader(buffer, 0, bufferLength, XmlDictionaryReaderQuotas.Max);
                    if (inclusivePrefix != null)
                        signatureReader.ReadStartElement("a");
                }
                signatureReader.ReadStartElement(XmlSignatureStrings.Signature, XmlSignatureStrings.Namespace);
                signatureReader.MoveToStartElement(XmlSignatureStrings.SignedInfo, XmlSignatureStrings.Namespace);
                signatureReader.StartCanonicalization(stream, false, GetInclusivePrefixes());
                signatureReader.Skip();
                signatureReader.EndCanonicalization();
                signatureReader.Close();
            }
        }

        public virtual void ComputeReferenceDigests()
        {
            if (_references.Count == 0)
                throw LogHelper.LogExceptionMessage(new CryptographicException("AtLeastOneReferenceRequired"));

            for (int i = 0; i < _references.Count; i++)
                _references[i].ComputeAndSetDigest();
        }

        public virtual void EnsureAllReferencesVerified()
        {
            for (int i = 0; i < _references.Count; i++)
            {
                if (!_references[i].Verified)
                    throw LogHelper.LogExceptionMessage(new CryptographicException("UnableToResolveReferenceUriForSignature, this.references[i].Uri"));
            }
        }

        protected string[] GetInclusivePrefixes()
        {
            return _canonicalizationMethodElement.GetInclusivePrefixes();
        }

        protected virtual string GetNamespaceForInclusivePrefix(string prefix)
        {
            if (Context == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException());

            if (prefix == null)
                throw LogHelper.LogArgumentNullException(nameof(prefix));

            return Context[prefix];
        }

        public void EnsureDigestValidity(string id, object resolvedXmlSource)
        {
            if (!EnsureDigestValidityIfIdMatches(id, resolvedXmlSource))
                throw LogHelper.LogExceptionMessage(new CryptographicException("RequiredTargetNotSigned, id"));
        }

        public virtual bool EnsureDigestValidityIfIdMatches(string id, object resolvedXmlSource)
        {
            for (int i = 0; i < _references.Count; i++)
            {
                if (_references[i].EnsureDigestValidityIfIdMatches(id, resolvedXmlSource))
                    return true;
            }

            return false;
        }


        public virtual bool HasUnverifiedReference(string id)
        {
            for (int i = 0; i < _references.Count; i++)
            {
                if (!_references[i].Verified && _references[i].ExtractReferredId() == id)
                    return true;
            }

            return false;
        }

        protected void ReadCanonicalizationMethod(XmlDictionaryReader reader)
        {
            _canonicalizationMethodElement.ReadFrom(reader, false);
        }

        public virtual void ReadFrom(XmlDictionaryReader reader, TransformFactory transformFactory)
        {
            SendSide = false;
            if (reader.CanCanonicalize)
            {
                CanonicalStream = new MemoryStream();
                reader.StartCanonicalization(CanonicalStream, false, null);
            }

            reader.MoveToStartElement(XmlSignatureStrings.SignedInfo, XmlSignatureStrings.Namespace);
            Prefix = reader.Prefix;
            Id = reader.GetAttribute(UtilityStrings.Id, null);
            reader.Read();

            ReadCanonicalizationMethod(reader);
            ReadSignatureMethod(reader);
            while (reader.IsStartElement(XmlSignatureStrings.Reference, XmlSignatureStrings.Namespace))
            {
                Reference reference = new Reference();
                reference.ReadFrom(reader, transformFactory);
                AddReference(reference);
            }

            reader.ReadEndElement(); // SignedInfo
            if (reader.CanCanonicalize)
                reader.EndCanonicalization();

            string[] inclusivePrefixes = GetInclusivePrefixes();
            if (inclusivePrefixes != null)
            {
                // Clear the canonicalized stream. We cannot use this while inclusive prefixes are
                // specified.
                CanonicalStream = null;
                Context = new Dictionary<string, string>(inclusivePrefixes.Length);
                for (int i = 0; i < inclusivePrefixes.Length; i++)
                    Context.Add(inclusivePrefixes[i], reader.LookupNamespace(inclusivePrefixes[i]));
            }
        }

        public virtual void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(Prefix, XmlSignatureStrings.SignedInfo, XmlSignatureStrings.Namespace);
            if (Id != null)
                writer.WriteAttributeString(UtilityStrings.Id, null, Id);

            WriteCanonicalizationMethod(writer);
            WriteSignatureMethod(writer);
            foreach (var reference in _references)
                reference.WriteTo(writer);

            writer.WriteEndElement(); // SignedInfo
        }

        protected void ReadSignatureMethod(XmlDictionaryReader reader)
        {
            _signatureMethodElement.ReadFrom(reader);
            SignatureMethod = _signatureMethodElement.Algorithm;
        }

        protected void WriteCanonicalizationMethod(XmlDictionaryWriter writer)
        {
            _canonicalizationMethodElement.WriteTo(writer);
        }

        protected void WriteSignatureMethod(XmlDictionaryWriter writer)
        {
            _signatureMethodElement.WriteTo(writer);
        }

        protected string Prefix { get; set; }

        protected Dictionary<string, string> Context { get; set; }
    }
}