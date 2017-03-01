//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Xml;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    public class Signature
    {
        SignedXml signedXml;
        string id;
        string prefix = SignedXml.DefaultPrefix;
        readonly SignatureValueElement signatureValueElement = new SignatureValueElement();
        readonly SignedInfo signedInfo;

        public Signature(SignedXml signedXml, SignedInfo signedInfo)
        {
            this.signedXml = signedXml;
            this.signedInfo = signedInfo;
        }

        public SecurityKey Key
        {
            get;set;
        }

        public string Id
        {
            get { return this.id; }
            set { this.id = value; }
        }

        public SignedInfo SignedInfo
        {
            get { return this.signedInfo; }
        }

        public ISignatureValueSecurityElement SignatureValue
        {
            get { return this.signatureValueElement; }
        }

        public byte[] GetSignatureBytes()
        {
            return this.signatureValueElement.Value;
        }

        public void ReadFrom(XmlDictionaryReader reader)
        {
            reader.MoveToStartElement(XmlSignatureStrings.Signature, XmlSignatureStrings.Namespace);
            this.prefix = reader.Prefix;
            this.Id = reader.GetAttribute(UtilityStrings.Id, null);
            reader.Read();

            this.signedInfo.ReadFrom(reader, signedXml.TransformFactory);
            this.signatureValueElement.ReadFrom(reader);

            reader.ReadEndElement(); // Signature
        }

        public void SetSignatureValue(byte[] signatureValue)
        {
            this.signatureValueElement.Value = signatureValue;
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(this.prefix, XmlSignatureStrings.Signature, XmlSignatureStrings.Namespace);
            if (this.id != null)
            {
                writer.WriteAttributeString(UtilityStrings.Id, null, this.id);
            }
            this.signedInfo.WriteTo(writer);
            this.signatureValueElement.WriteTo(writer);

            writer.WriteEndElement(); // Signature
        }

        sealed class SignatureValueElement : ISignatureValueSecurityElement
        {
            string id;
            string prefix = SignedXml.DefaultPrefix;
            byte[] signatureValue;
            string signatureText;

            public bool HasId
            {
                get { return true; }
            }

            public string Id
            {
                get { return this.id; }
                set { this.id = value; }
            }

            internal byte[] Value
            {
                get { return this.signatureValue; }
                set
                {
                    this.signatureValue = value;
                    this.signatureText = null;
                }
            }

            public void ReadFrom(XmlDictionaryReader reader)
            {
                reader.MoveToStartElement(XmlSignatureStrings.SignatureValue, XmlSignatureStrings.Namespace);
                this.prefix = reader.Prefix;
                this.Id = reader.GetAttribute(UtilityStrings.Id, null);
                reader.Read();

                this.signatureText = reader.ReadString();
                this.signatureValue = System.Convert.FromBase64String(signatureText.Trim());

                reader.ReadEndElement(); // SignatureValue
            }

            public void WriteTo(XmlDictionaryWriter writer)
            {
                writer.WriteStartElement(this.prefix, XmlSignatureStrings.SignatureValue, XmlSignatureStrings.Namespace);
                if (this.id != null)
                {
                    writer.WriteAttributeString(UtilityStrings.Id, null, this.id);
                }
                if (this.signatureText != null)
                {
                    writer.WriteString(this.signatureText);
                }
                else
                {
                    writer.WriteBase64(this.signatureValue, 0, this.signatureValue.Length);
                }
                writer.WriteEndElement(); // SignatureValue
            }

            byte[] ISignatureValueSecurityElement.GetSignatureValue()
            {
                return this.Value;
            }
        }
    }
}