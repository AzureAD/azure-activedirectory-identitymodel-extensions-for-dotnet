//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    class StrTransform : Transform
    {
        readonly bool includeComments;
        string inclusiveNamespacesPrefixList;
        string[] inclusivePrefixes;
        string prefix = XmlSignatureStrings.Prefix;
        TranformationParameters transformationParameters;

        public StrTransform()
        {
            this.transformationParameters = new TranformationParameters();
            this.includeComments = false;
        }

        public override string Algorithm
        {
            get
            {
                return SecurityAlgorithms.StrTransform;
            }
        }

        public bool IncludeComments
        {
            get
            {
                return this.includeComments;
            }
        }

        public string InclusiveNamespacesPrefixList
        {
            get
            {
                return this.inclusiveNamespacesPrefixList;
            }
            set
            {
                this.inclusiveNamespacesPrefixList = value;
                this.inclusivePrefixes = TokenizeInclusivePrefixList(value);
            }
        }

        public override bool NeedsInclusiveContext
        {
            get { return GetInclusivePrefixes() != null; }
        }

        public string[] GetInclusivePrefixes()
        {
            return this.inclusivePrefixes;
        }

        CanonicalizationDriver GetConfiguredDriver(SignatureResourcePool resourcePool)
        {
            CanonicalizationDriver driver = resourcePool.TakeCanonicalizationDriver();
            driver.IncludeComments = this.IncludeComments;
            driver.SetInclusivePrefixes(this.inclusivePrefixes);
            return driver;
        }

        public override object Process(object input, SignatureResourcePool resourcePool)
        {
            if (input is XmlReader)
            {
                CanonicalizationDriver driver = GetConfiguredDriver(resourcePool);
                driver.SetInput(input as XmlReader);
                return driver.GetMemoryStream();
            }
            else if (input is ISecurityElement)
            {
                MemoryStream stream = new MemoryStream();
                XmlDictionaryWriter utf8Writer = resourcePool.TakeUtf8Writer();
                utf8Writer.StartCanonicalization(stream, false, null);
                (input as ISecurityElement).WriteTo(utf8Writer);
                utf8Writer.EndCanonicalization();
                stream.Seek(0, SeekOrigin.Begin);
                return stream;
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new NotSupportedException("UnsupportedInputTypeForTransform"));
                //throw LogHelper.LogExceptionMessage(new NotSupportedException(SR.GetString(SR.UnsupportedInputTypeForTransform, input.GetType())));
            }
        }

        public override byte[] ProcessAndDigest(object input, SignatureResourcePool resourcePool, string digestAlgorithm)
        {
            HashAlgorithm hash = resourcePool.TakeHashAlgorithm(digestAlgorithm);
            ProcessAndDigest(input, resourcePool, hash);
            return hash.Hash;
        }

        public void ProcessAndDigest(object input, SignatureResourcePool resourcePool, HashAlgorithm hash)
        {
            HashStream hashStream = resourcePool.TakeHashStream(hash);

            XmlReader reader = input as XmlReader;
            if (reader != null)
            {
                ProcessReaderInput(reader, resourcePool, hashStream);
            }
            else if (input is ISecurityElement)
            {
                XmlDictionaryWriter utf8Writer = resourcePool.TakeUtf8Writer();
                utf8Writer.StartCanonicalization(hashStream, this.IncludeComments, GetInclusivePrefixes());
                (input as ISecurityElement).WriteTo(utf8Writer);
                utf8Writer.EndCanonicalization();
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new NotSupportedException("UnsupportedInputTypeForTransform"));
                //throw LogHelper.LogExceptionMessage(new NotSupportedException(SR.GetString(SR.UnsupportedInputTypeForTransform, input.GetType())));
            }

            hashStream.FlushHash();
        }

        void ProcessReaderInput(XmlReader reader, SignatureResourcePool resourcePool, HashStream hashStream)
        {
            reader.MoveToContent();
            XmlDictionaryReader dictionaryReader = reader as XmlDictionaryReader;
            if (dictionaryReader != null && dictionaryReader.CanCanonicalize)
            {
                dictionaryReader.StartCanonicalization(hashStream, this.IncludeComments, GetInclusivePrefixes());
                dictionaryReader.Skip();
                dictionaryReader.EndCanonicalization();
            }
            else
            {
                CanonicalizationDriver driver = GetConfiguredDriver(resourcePool);
                driver.SetInput(reader);
                driver.WriteTo(hashStream);
            }
        }

        public override void ReadFrom(XmlDictionaryReader reader, bool preserveComments)
        {
            reader.MoveToStartElement(XmlSignatureStrings.Transform, XmlSignatureStrings.Namespace);
            this.prefix = reader.Prefix;
            bool isEmptyElement = reader.IsEmptyElement;
            string algorithm = reader.GetAttribute(XmlSignatureStrings.Algorithm, null);
            if (algorithm != this.Algorithm)
            {
                throw LogHelper.LogExceptionMessage(new NotSupportedException("AlgorithmMismatchForTransform"));
                //throw LogHelper.LogExceptionMessage(new CryptographicException(SR.GetString(SR.AlgorithmMismatchForTransform)));
            }

            reader.MoveToContent();
            reader.Read();

            if (!isEmptyElement)
            {
                if (reader.IsStartElement(XmlSignatureStrings.TransformationParameters, XmlSignatureStrings.SecurityJan2004Namespace))
                    this.transformationParameters.ReadFrom(reader);

                reader.MoveToContent();
                reader.ReadEndElement();
            }
        }

        public override void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(prefix, XmlSignatureStrings.Transform, XmlSignatureStrings.Namespace);
            writer.WriteStartAttribute(XmlSignatureStrings.Algorithm, null);
            writer.WriteString(this.Algorithm);
            writer.WriteEndAttribute();
            this.transformationParameters.WriteTo(writer);
            writer.WriteEndElement(); // Transform
        }

        static string[] TokenizeInclusivePrefixList(string prefixList)
        {
            if (prefixList == null)
            {
                return null;
            }
            string[] prefixes = prefixList.Split(null);
            int count = 0;
            for (int i = 0; i < prefixes.Length; i++)
            {
                string prefix = prefixes[i];
                if (prefix == "#default")
                {
                    prefixes[count++] = string.Empty;
                }
                else if (prefix.Length > 0)
                {
                    prefixes[count++] = prefix;
                }
            }
            if (count == 0)
            {
                return null;
            }
            else if (count == prefixes.Length)
            {
                return prefixes;
            }
            else
            {
                string[] result = new string[count];
                Array.Copy(prefixes, result, count);
                return result;
            }
        }
    }

    class TranformationParameters
    {
        public TranformationParameters()
        {
        }

        public string CanonicalizationAlgorithm
        {
            get { return SecurityAlgorithmStrings.ExclusiveC14n; }
        }

        public void ReadFrom(XmlDictionaryReader reader)
        {
            reader.MoveToContent();
            reader.MoveToStartElement(XmlSignatureStrings.TransformationParameters, XmlSignatureStrings.SecurityJan2004Namespace);
            string prefix = reader.Prefix;

            bool skipReadingTransformEnd = reader.IsEmptyElement;
            reader.ReadStartElement();

            if (reader.IsStartElement(XmlSignatureStrings.CanonicalizationMethod, XmlSignatureStrings.Namespace))
            {

                string algorithm = reader.GetAttribute(XmlSignatureStrings.Algorithm, null);
                // Canonicalization Method can be empty.
                // <elementNOTempty></elementNOTempty>
                // <elementEmpty/>
                bool skipReadingC14End = reader.IsEmptyElement;

                reader.ReadStartElement();

                if (algorithm == null)
                {
                    throw LogHelper.LogExceptionMessage(new CryptographicException("dictionaryManager.XmlSignatureDictionary.CanonicalizationMethod"));
                    //throw LogHelper.LogExceptionMessage(new CryptographicException(
                    //    SR.GetString(SR.RequiredAttributeMissing, dictionaryManager.XmlSignatureDictionary.Algorithm, dictionaryManager.XmlSignatureDictionary.CanonicalizationMethod)));
                }

                if (algorithm != this.CanonicalizationAlgorithm)
                {
                    throw LogHelper.LogExceptionMessage(new CryptographicException("AlgorithmMismatchForTransform"));
                    //throw LogHelper.LogExceptionMessage(new CryptographicException(SR.GetString(SR.AlgorithmMismatchForTransform)));
                }


                // ReadEndElement() called only if element was not empty
                if (!skipReadingC14End)
                {
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }
            }

            // If it was empty, don't read endElement as it was read in ReadStartElement
            if (!skipReadingTransformEnd)
            {
                reader.MoveToContent();
                reader.ReadEndElement();
            }
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(XmlSignatureStrings.SecurityJan2004Prefix, XmlSignatureStrings.TransformationParameters, XmlSignatureStrings.SecurityJan2004Namespace);  //<wsse:TransformationParameters>
            writer.WriteStartElement(XmlSignatureStrings.Prefix, XmlSignatureStrings.CanonicalizationMethod, XmlSignatureStrings.Namespace);
            writer.WriteStartAttribute(XmlSignatureStrings.Algorithm, null);
            writer.WriteString(SecurityAlgorithmStrings.ExclusiveC14n);
            writer.WriteEndAttribute();
            writer.WriteEndElement(); // CanonicalizationMethod 
            writer.WriteEndElement(); // TransformationParameters
        }
    }
}
