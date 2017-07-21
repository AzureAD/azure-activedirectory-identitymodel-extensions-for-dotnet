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

#if EncryptedTokens

using System;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{

    /// <summary>
    /// This class implements a deserialization for: EncryptedData as defined in section 3.4 of http://www.w3.org/TR/2002/REC-xmlenc-core-2002120
    /// </summary>
    internal class EncryptedDataElement : EncryptedTypeElement
    {
        public static bool CanReadFrom(XmlReader reader)
        {
            return reader != null && reader.IsStartElement(
                XmlEncryptionConstants.Elements.EncryptedData,
                XmlEncryptionConstants.Namespace);
        }

        public EncryptedDataElement() { }

        /// <summary>
        /// Decrypts the data
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">When algorithm is null</exception>
        /// <exception cref="InvalidOperationException">When no cipher data has been read</exception>
        public byte[] Decrypt(SymmetricAlgorithm algorithm)
        {
            if (algorithm == null)
                LogArgumentNullException(nameof(algorithm));

            if (CipherData == null || CipherData.CipherValue == null)
                LogExceptionMessage(new XmlEncryptionException("no cipherData to decrypt"));

            byte[] cipherText = CipherData.CipherValue;

            return ExtractIVAndDecrypt(algorithm, cipherText, 0, cipherText.Length);
        }

        public void Encrypt(SymmetricAlgorithm algorithm, byte[] buffer, int offset, int length)
        {
            byte[] iv;
            byte[] cipherText;
            GenerateIVAndEncrypt(algorithm, buffer, offset, length, out iv, out cipherText);
            CipherData.SetCipherValueFragments(iv, cipherText);
        }

        static byte[] ExtractIVAndDecrypt(SymmetricAlgorithm algorithm, byte[] cipherText, int offset, int count)
        {
            byte[] iv = new byte[algorithm.BlockSize / 8];

            //
            // Make sure cipherText has enough bytes after the offset, for Buffer.BlockCopy to copy.
            //
            if (cipherText.Length - offset < iv.Length)
                LogExceptionMessage(new XmlEncryptionException("cipherText.Length"));

            Buffer.BlockCopy(cipherText, offset, iv, 0, iv.Length);
            // TODO - not available in .net 1.4
            // algorithm.Padding = PaddingMode.ISO10126;
            algorithm.Mode = CipherMode.CBC;

            ICryptoTransform decrTransform = null;
            byte[] plainText = null;

            try
            {
                decrTransform = algorithm.CreateDecryptor(algorithm.Key, iv);
                plainText = decrTransform.TransformFinalBlock(cipherText, offset + iv.Length, count - iv.Length);
            }
            finally
            {
                if (decrTransform != null)
                    decrTransform.Dispose();
            }

            return plainText;
        }

        static void GenerateIVAndEncrypt(SymmetricAlgorithm algorithm, byte[] plainText, int offset, int length, out byte[] iv, out byte[] cipherText)
        {
            RandomNumberGenerator random = CryptoHelper.RandomNumberGenerator;
            int ivSize = algorithm.BlockSize / 8;
            iv = new byte[ivSize];
            random.GetBytes(iv);
            algorithm.Padding = PaddingMode.PKCS7;
            algorithm.Mode = CipherMode.CBC;
            ICryptoTransform encrTransform = algorithm.CreateEncryptor(algorithm.Key, iv);
            cipherText = encrTransform.TransformFinalBlock(plainText, offset, length);
            encrTransform.Dispose();
        }

        public SecurityKey Key { get; set; }

        public override void ReadExtensions(XmlDictionaryReader reader)
        {
            // nothing to do here
        }

        /// <summary>
        /// Reads an EncryptedData element
        /// </summary>
        /// <param name="reader"></param>
        /// <exception cref="ArgumentNullException">When reader is null</exception>
        public override void ReadXml(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlEncryptionConstants.Elements.EncryptedData, XmlEncryptionConstants.Namespace);

            // <EncryptedData> extends <EncryptedType>
            // base will read the start element and the end element.
            base.ReadXml(reader);
        }

        /// <summary>
        /// Writes the EncryptedData element
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="securityTokenSerializer"></param>
        /// <exception cref="ArgumentNullException">When securityTokenSerializer is null</exception>
        /// <exception cref="InvalidOperationException">When KeyIdentifier is null</exception>
        public virtual void WriteXml(XmlWriter writer)
        {
            if (writer == null)
                LogArgumentNullException(nameof(writer));

            // TODO - SecurityKey reader / writer?
            //if ( KeyIdentifier == null )
            //{
            //    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError( new InvalidOperationException( SR.GetString( SR.ID6001 ) ) );
            //}

            // <EncryptedData>
            writer.WriteStartElement(XmlEncryptionConstants.Prefix, XmlEncryptionConstants.Elements.EncryptedData, XmlEncryptionConstants.Namespace);

            if (!string.IsNullOrEmpty(Id))
                writer.WriteAttributeString(XmlEncryptionConstants.Attributes.Id, null, Id);

            if (!string.IsNullOrEmpty(Type))
                writer.WriteAttributeString(XmlEncryptionConstants.Attributes.Type, null, Type);

            if (EncryptionMethod != null)
                EncryptionMethod.WriteXml(writer);

            //TODO - SecurityKey reader / writer?
            //if ( KeyIdentifier != null )
            //{
            //    securityTokenSerializer.WriteKeyIdentifier( XmlDictionaryWriter.CreateDictionaryWriter( writer ), KeyIdentifier );
            //}

            CipherData.WriteXml(writer);

            // <EncryptedData> 
            writer.WriteEndElement();
        }
    }
}

#endif