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

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// EncryptedAssertionHandler can be used for interactions with SAML2 encrypted assertion.
    /// </summary>
    internal class EncryptedAssertionHandler : IEncryptedAssertionHandler
    {
        /// <summary>
        /// Encrypts provided SAML2 <paramref name="assertionData"/> bytes using the <paramref name="encryptingCredentials"/> instance.
        /// </summary>
        /// <param name="assertionData">A byte array representation of SAML2 assertion string to be encrypted.</param>
        /// <param name="encryptingCredentials">An ecryption credentials instance.</param>
        /// <returns>A <see cref="Saml2EncryptedAssertion"/> instance.</returns>
        public Saml2EncryptedAssertion EncryptAssertion(byte[] assertionData, EncryptingCredentials encryptingCredentials)
        {
            ValidateEncryptingCredentials(encryptingCredentials);

            var encryptedAssertion = new Saml2EncryptedAssertion();
            var sessionKey = CreateSessionKey(encryptingCredentials);
            encryptedAssertion.EncryptedData = CreateEncryptedData(assertionData, encryptingCredentials, sessionKey);
            encryptedAssertion.EncryptedKey = CreateEncryptedKey(encryptingCredentials, sessionKey, encryptedAssertion.EncryptedData.Id);
            return encryptedAssertion;
        }

        /// <summary>
        /// Decrypts provided <paramref name="assertion"/> using the <paramref name="validationParameters"/> instance.
        /// </summary>
        /// <param name="assertion">A <see cref="Saml2EncryptedAssertion"/> instance to be decrypted.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/> instance to be used to decrypt <paramref name="assertion"/>.</param>
        /// <param name="assertionString">A string representation of an <paramref name="assertion"/>.</param>
        /// <returns>A Saml2 assertion string.</returns>
        /// <remarks>
        /// <see cref="TokenValidationParameters.TokenDecryptionKey"/> will be used as a decryption key in case that <see cref="TokenValidationParameters.TokenDecryptionKeyResolver"/> 
        /// delegate is not set. <see cref="TokenValidationParameters.CryptoProviderFactory"/> will be used as a cryto provider factory, if set.
        /// </remarks>
        public string DecryptAssertion(Saml2EncryptedAssertion assertion, TokenValidationParameters validationParameters, string assertionString)
        {
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            ValidateEncryptedAssertion(assertion);

            SecurityKey key = null;
            // Support only for a single key for now
            if (validationParameters.TokenDecryptionKeyResolver != null)
            {
                key = validationParameters.TokenDecryptionKeyResolver(assertionString, null, assertion.EncryptedData.KeyInfo.KeyName, validationParameters).FirstOrDefault();
            }
            else
                key = validationParameters.TokenDecryptionKey;

            if (key == null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogMessages.IDX13622));

            var cryptoProviderFactory = validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory;
            if (cryptoProviderFactory == null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogMessages.IDX13621));

            // There is no EncryptedKey - Relying Party must be able to locally determine the decryption key
            if (assertion.EncryptedKey == null)
            {
                if (!cryptoProviderFactory.IsSupportedAlgorithm(assertion.EncryptedData.EncryptionMethod.KeyAlgorithm, key))
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogHelper.FormatInvariant(LogMessages.IDX13623, assertion.EncryptedData.EncryptionMethod.KeyAlgorithm, key)));

                var decryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(key, assertion.EncryptedData.EncryptionMethod.KeyAlgorithm);
                var decryptedAssertionBytes = decryptionProvider.Decrypt(assertion.EncryptedData.CipherData.CipherValue, null, null, null);
                return Encoding.UTF8.GetString(decryptedAssertionBytes);
            }
            else // Session key is wrapped
            {
                if (!cryptoProviderFactory.IsSupportedAlgorithm(assertion.EncryptedKey.EncryptionMethod.KeyAlgorithm, key))
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogHelper.FormatInvariant(LogMessages.IDX13623, assertion.EncryptedKey.EncryptionMethod.KeyAlgorithm, key)));

                var keyWrapProvider = cryptoProviderFactory.CreateKeyWrapProviderForUnwrap(key, assertion.EncryptedKey.EncryptionMethod.KeyAlgorithm);
                var unwrappedKey = keyWrapProvider.UnwrapKey(assertion.EncryptedKey.CipherData.CipherValue);
                var sessionKey = new SymmetricSecurityKey(unwrappedKey);

                var decryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(sessionKey, assertion.EncryptedData.EncryptionMethod.KeyAlgorithm);
                var decryptedAssertionBytes = decryptionProvider.Decrypt(assertion.EncryptedData.CipherData.CipherValue, null, null, null);
                return Encoding.UTF8.GetString(decryptedAssertionBytes);
            }
        }


        /// <summary>
        /// Reads provided SAML2 <paramref name="assertion"/> string into a <see cref="Saml2EncryptedAssertion"/> instance.
        /// </summary>
        /// <param name="assertion">A SAML2 assertion string.</param>
        /// <returns>A <see cref="Saml2EncryptedAssertion"/> instance.</returns>
        public Saml2EncryptedAssertion ReadEncryptedAssertion(string assertion)
        {
            using (var reader = XmlUtil.CreateDefaultXmlDictionaryReader(assertion))
            {
                var encryptedAssertion = new Saml2EncryptedAssertion();
                encryptedAssertion.ReadXml(reader);
                return encryptedAssertion;
            }
        }

        /// <summary>
        /// Writes provided <paramref name="assertion"/> into the <paramref name="writer"/>.
        /// </summary>
        /// <param name="writer">An XML writer instance.</param>
        /// <param name="assertion">A <see cref="Saml2EncryptedAssertion"/> instance to be writen into an XML writer.</param>
        /// <param name="samlPrefix"> A saml2 xml prefix.</param>
        public void WriteAssertionToXml(XmlWriter writer, Saml2EncryptedAssertion assertion, string samlPrefix)
        {
            writer.WriteStartElement(samlPrefix, Saml2Constants.Elements.EncryptedAssertion, Saml2Constants.Namespace);
            assertion.WriteXml(writer);
            writer.WriteEndElement();
        }

        #region Helper methods
        private void ValidateEncryptingCredentials(EncryptingCredentials encryptingCredentials)
        {
            if (encryptingCredentials == null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogMessages.IDX13624));

            // Only AES-GCM is supported as a data encryption algorithm
            if (!(SecurityAlgorithms.Aes128Gcm.Equals(encryptingCredentials.Enc, StringComparison.Ordinal)
                || (SecurityAlgorithms.Aes192Gcm.Equals(encryptingCredentials.Enc, StringComparison.Ordinal))
                || (SecurityAlgorithms.Aes256Gcm.Equals(encryptingCredentials.Enc, StringComparison.Ordinal))))
            {
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogHelper.FormatInvariant(LogMessages.IDX13625, SecurityAlgorithms.Aes128Gcm, SecurityAlgorithms.Aes192Gcm, SecurityAlgorithms.Aes256Gcm, encryptingCredentials.Enc)));
            }

            if (encryptingCredentials.Key is SymmetricSecurityKey)
            {
                // If SymmetricSecurityKey is used (pre-shared session key) - Algorithm should be set to None
                if (!encryptingCredentials.Alg.Equals(SecurityAlgorithms.None, StringComparison.Ordinal))
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogHelper.FormatInvariant(LogMessages.IDX13626, SecurityAlgorithms.None, encryptingCredentials.Alg)));

            }
            else if (encryptingCredentials.Key is AsymmetricSecurityKey)
            {
                if (!(SecurityAlgorithms.RsaOaepMgf1pKeyWrap.Equals(encryptingCredentials.Alg, StringComparison.Ordinal)
                || (SecurityAlgorithms.RsaOaepKeyWrap.Equals(encryptingCredentials.Alg, StringComparison.Ordinal))))
                {
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogHelper.FormatInvariant(LogMessages.IDX13627, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, encryptingCredentials.Alg)));
                }
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogMessages.IDX13628));
            }
        }

        private void ValidateEncryptedAssertion(Saml2EncryptedAssertion encryptedAssertion)
        {
            if (encryptedAssertion.EncryptedData == null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogMessages.IDX13610));

            // By xmlenc-core1 standard EncryptionMethod is an optional element.
            // "If the element is absent, the encryption algorithm must be known by the recipient or the decryption will fail"
            // As there is no support for users to provide the encryption algorithm - we will treat the encryption algorithm as required for now
            if (string.IsNullOrEmpty(encryptedAssertion.EncryptedData.EncryptionMethod.KeyAlgorithm))
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogMessages.IDX13611));

            // CipherValue is required Element
            if (encryptedAssertion.EncryptedData.CipherData.CipherValue == null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogMessages.IDX13612));

            // If present - type should be http://www.w3.org/2001/04/xmlenc#Element
            if (!string.IsNullOrEmpty(encryptedAssertion.EncryptedData.Type) && !encryptedAssertion.EncryptedData.Type.Equals(XmlEncryptionConstants.EncryptedDataTypes.Element))
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogHelper.FormatInvariant(LogMessages.IDX13613, encryptedAssertion.EncryptedData.Type)));

            // EncryptedKey is present - there are additional checks
            if (encryptedAssertion.EncryptedKey != null)
            {
                // By xmlenc-core1 standard EncryptionMethod is an optional element.
                // "If the element is absent, the encryption algorithm must be known by the recipient or the decryption will fail"
                // As there is no support for users to provide the encryption algorithm - we will treat the encryption algorithm as required for now
                if (string.IsNullOrEmpty(encryptedAssertion.EncryptedKey.EncryptionMethod.KeyAlgorithm))
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogMessages.IDX13611));

                // CipherValue is a required Element
                if (encryptedAssertion.EncryptedKey.CipherData.CipherValue == null)
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogMessages.IDX13612));

                // If present - type should be http://www.w3.org/2001/04/xmlenc#EncryptedKey
                if (!string.IsNullOrEmpty(encryptedAssertion.EncryptedKey.Type) && !encryptedAssertion.EncryptedKey.Type.Equals(XmlEncryptionConstants.EncryptedDataTypes.EncryptedKey))
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogHelper.FormatInvariant(LogMessages.IDX13614, encryptedAssertion.EncryptedKey.Type)));

                // If EncryptedKey contains DataReferences - then at least one DataReference should reference the EncrytedData element
                if (encryptedAssertion.EncryptedKey.ReferenceList.Any(item => item is DataReference))
                {
                    // If the above is true, EncryptedData must have an ID
                    if (string.IsNullOrEmpty(encryptedAssertion.EncryptedData.Id))
                        throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogMessages.IDX13615));

                    // At least one DataReference should reference the EncrytedData element
                    var isEncryptedDataReferenced = encryptedAssertion.EncryptedKey.ReferenceList.Any(item => item is DataReference && item.Uri.Equals(encryptedAssertion.EncryptedData.Id));
                    if (!isEncryptedDataReferenced)
                        throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogMessages.IDX13616));
                }

                // If EncryptedData -> KeyInfo has RetrievalMethodUri element - then it should reference the EncryptedKey
                if (!string.IsNullOrEmpty(encryptedAssertion.EncryptedData.KeyInfo.RetrievalMethodUri))
                {
                    // If the above is true, EncryptedKey must have an ID
                    if (string.IsNullOrEmpty(encryptedAssertion.EncryptedKey.Id))
                        throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogMessages.IDX13617));

                    // RetrievalMethodUri element should reference the EncryptedKey
                    if (!encryptedAssertion.EncryptedData.KeyInfo.RetrievalMethodUri.Equals(encryptedAssertion.EncryptedKey.Id, StringComparison.Ordinal))
                        throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogHelper.FormatInvariant(LogMessages.IDX13618, encryptedAssertion.EncryptedData.KeyInfo.RetrievalMethodUri, encryptedAssertion.EncryptedKey.Id)));
                }
            }
        }

        private EncryptedData CreateEncryptedData(byte[] assertionData, EncryptingCredentials encryptingCredentials, SymmetricSecurityKey sessionKey)
        {
            if (encryptingCredentials == null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogMessages.IDX13624));

            var encryptedData = new EncryptedData();
            string algorithm = encryptingCredentials.Enc;

            // SymmetricSecurityKey is provided:
            // Session key will not be serialized, but KeyName will be set if available
            if (encryptingCredentials.Key is SymmetricSecurityKey)
            {
                encryptedData.KeyInfo.KeyName = sessionKey.KeyId;
            }
            // AsymmetricSecurityKey is provided:
            else if (encryptingCredentials.Key is AsymmetricSecurityKey)
            {
                encryptedData.KeyInfo.RetrievalMethodUri = encryptingCredentials.Key.KeyId;
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogHelper.FormatInvariant(LogMessages.IDX13606, encryptingCredentials.Key)));
            }

            var cryptoProviderFactory = encryptingCredentials.CryptoProviderFactory ?? encryptingCredentials.Key.CryptoProviderFactory;

            if (cryptoProviderFactory == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX13600));

            if (!cryptoProviderFactory.IsSupportedAlgorithm(algorithm, sessionKey))
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogHelper.FormatInvariant(LogMessages.IDX13601, algorithm, sessionKey)));

            // Encrypt assertion data
            AuthenticatedEncryptionResult authenticatedEncryptionResult = null;
            AuthenticatedEncryptionProvider authenticatedEncryptionProvider = null;
            try
            {
                authenticatedEncryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(sessionKey, algorithm);

                if (authenticatedEncryptionProvider == null)
                    throw new Saml2SecurityTokenEncryptedAssertionEncryptionException();
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogMessages.IDX13602, ex));
            }

            try
            {
                authenticatedEncryptionResult = authenticatedEncryptionProvider.Encrypt(assertionData, null);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogHelper.FormatInvariant(LogMessages.IDX13603, algorithm, sessionKey), ex));
            }

            // Populate EncryptedData
            encryptedData.CipherData.CipherValue = Utility.ConcatByteArrays(authenticatedEncryptionResult.IV, authenticatedEncryptionResult.Ciphertext, authenticatedEncryptionResult.AuthenticationTag);
            encryptedData.EncryptionMethod = new EncryptionMethod(algorithm);
            encryptedData.Type = XmlEncryptionConstants.EncryptedDataTypes.Element;
            encryptedData.Id = new Saml2Id().Value;

            return encryptedData;
        }

        private EncryptedKey CreateEncryptedKey(EncryptingCredentials encryptingCredentials, SymmetricSecurityKey sessionKey, string encryptedDataId)
        {
            if (encryptingCredentials == null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogMessages.IDX13624));

            if (sessionKey == null)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogMessages.IDX13629));

            // SymmetricSecurityKey is provided:
            // Session key will not be serialized - EncryptedKey should be null
            if (encryptingCredentials.Key is SymmetricSecurityKey)
            {
                return null;
            }
            else if (!(encryptingCredentials.Key is AsymmetricSecurityKey))
            {
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogHelper.FormatInvariant(LogMessages.IDX13606, encryptingCredentials.Key)));
            }
            // AsymmetricSecurityKey is provided: Session key will be wrapped with provided AsymmetricSecurityKey
            else  // (encryptingCredentials.Key is AsymmetricSecurityKey)
            {
                var cryptoProviderFactory = encryptingCredentials.CryptoProviderFactory ?? encryptingCredentials.Key.CryptoProviderFactory;
                var key = encryptingCredentials.Key;
                var algorithm = encryptingCredentials.Alg;

                if (cryptoProviderFactory == null)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX13600));

                if (!cryptoProviderFactory.IsSupportedAlgorithm(algorithm, key))
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogHelper.FormatInvariant(LogMessages.IDX13601, algorithm, key)));

                var encryptedKey = new EncryptedKey
                {
                    Id = key.KeyId,
                    EncryptionMethod = new EncryptionMethod(algorithm)
                };

                // Wrap the sessionKey
                try
                {
                    var keyWrapProvider = cryptoProviderFactory.CreateKeyWrapProvider(key, algorithm);
                    var wrappedKey = keyWrapProvider.WrapKey(sessionKey.Key);
                    encryptedKey.CipherData.CipherValue = wrappedKey;
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogHelper.FormatInvariant(LogMessages.IDX13603, algorithm, sessionKey), ex));
                }

                // Add reference from EncrypedKey to EncryptedData
                encryptedKey.AddReference(new DataReference(encryptedDataId));

                // Set Digest method for EncryptedKey (AES-GCM)
                if (SecurityAlgorithms.RsaOaepMgf1pKeyWrap.Equals(encryptingCredentials.Alg, StringComparison.Ordinal)
                    || SecurityAlgorithms.RsaOaepKeyWrap.Equals(encryptingCredentials.Alg, StringComparison.Ordinal))
                    encryptedKey.EncryptionMethod.DigestMethod = SecurityAlgorithms.Sha1Digest;

                // Set X509CertificateData if available
                if (encryptingCredentials.Key is X509SecurityKey)
                {
                    var cert = (encryptingCredentials.Key as X509SecurityKey).Certificate;
                    var x509Data = new X509Data(cert);
                    encryptedKey.KeyInfo.X509Data.Add(x509Data);
                }

                return encryptedKey;
            }
        }

        private SymmetricSecurityKey CreateSessionKey(EncryptingCredentials encryptingCredentials)
        {
            if (encryptingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptingCredentials));

            string algorithm = encryptingCredentials.Enc;

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            SymmetricSecurityKey sessionKey;

            // SymmetricSecurityKey is provided:
            // Pre-shared symmetric key (session key) is used to encrypt an assertion
            if (encryptingCredentials.Key is SymmetricSecurityKey)
            {
                sessionKey = (SymmetricSecurityKey)encryptingCredentials.Key;
            }
            // AsymmetricSecurityKey is provided:
            // New session key will be created to encrypt an assertion
            else if (encryptingCredentials.Key is AsymmetricSecurityKey)
            {
                int keySize = -1;

                if (SecurityAlgorithms.Aes128Gcm.Equals(algorithm, StringComparison.Ordinal))
                    keySize = 128;
                else if (SecurityAlgorithms.Aes192Gcm.Equals(algorithm, StringComparison.Ordinal))
                    keySize = 192;
                else if (SecurityAlgorithms.Aes256Gcm.Equals(algorithm, StringComparison.Ordinal))
                    keySize = 256;

                if (keySize == -1)
                {
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogHelper.FormatInvariant(LogMessages.IDX13607, algorithm)));
                }

                var aes = Aes.Create();
                aes.KeySize = keySize;
                aes.GenerateKey();
                sessionKey = new SymmetricSecurityKey(aes.Key);
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionEncryptionException(LogHelper.FormatInvariant(LogMessages.IDX13606, encryptingCredentials.Key)));
            }

            return sessionKey;
        }
        #endregion
    }
}
