// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;
using static Microsoft.IdentityModel.Xml.XmlUtil;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents a XmlDsig Signature element as per: https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Signature
    /// </summary>
    public class Signature : DSigElement
    {
        private string _signatureValue;
        private SignedInfo _signedInfo;

        /// <summary>
        /// Initializes a <see cref="Signature"/> instance.
        /// </summary>
        public Signature()
        {
        }

        /// <summary>
        /// Initializes a <see cref="Signature"/> instance.
        /// </summary>
        /// <param name="signedInfo">associated with this Signature.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="signedInfo"/> if null.</exception>
        public Signature(SignedInfo signedInfo)
        {
            SignedInfo = signedInfo;
        }

        /// <summary>
        /// Gets or sets the KeyInfo
        /// </summary>
        public KeyInfo KeyInfo
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the SignatureValue
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null or empty.</exception>
        public string SignatureValue
        {
            get => _signatureValue;
            set => _signatureValue = string.IsNullOrEmpty(value) ? throw LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets the <see cref="SignedInfo"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null.</exception>
        public SignedInfo SignedInfo
        {
            get => _signedInfo;
            set => _signedInfo = value ?? throw LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Verifies the signature over the SignedInfo.
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/> to use for cryptographic operations.</param>
        /// <exception cref="ArgumentNullException"> if <paramref name="key"/> is null.</exception>
        /// <exception cref="XmlValidationException"> if <see cref="SignedInfo"/> null.</exception>
        /// <exception cref="XmlValidationException"> if <see cref="SignedInfo.SignatureMethod"/> is not supported.</exception>
        /// <exception cref="XmlValidationException"> if signature does not validate.</exception>
        public void Verify(SecurityKey key)
        {
            if (key == null)
                throw LogArgumentNullException(nameof(key));

            Verify(key, key.CryptoProviderFactory);
        }

        /// <summary>
        /// Verifies the signature over the SignedInfo.
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/> to use for cryptographic operations.</param>
        /// <param name="cryptoProviderFactory">the <see cref="CryptoProviderFactory"/> to obtain cryptographic operators.</param>
        /// <exception cref="ArgumentNullException"> if <paramref name="key"/> is null.</exception>
        /// <exception cref="ArgumentNullException"> if <paramref name="cryptoProviderFactory"/> is null.</exception>
        /// <exception cref="XmlValidationException"> if <see cref="SignedInfo"/> null.</exception>
        /// <exception cref="XmlValidationException"> if <see cref="SignedInfo.SignatureMethod"/> is not supported.</exception>
        /// <exception cref="XmlValidationException"> if signature does not validate.</exception>
        public void Verify(SecurityKey key, CryptoProviderFactory cryptoProviderFactory)
        {
            if (key == null)
                throw LogArgumentNullException(nameof(key));

            if (cryptoProviderFactory == null)
                throw LogArgumentNullException(nameof(cryptoProviderFactory));

            if (SignedInfo == null)
                throw LogValidationException(LogMessages.IDX30212);

            if (!cryptoProviderFactory.IsSupportedAlgorithm(SignedInfo.SignatureMethod, key))
                throw LogValidationException(LogMessages.IDX30207, SignedInfo.SignatureMethod, cryptoProviderFactory.GetType());

            var signatureProvider = cryptoProviderFactory.CreateForVerifying(key, SignedInfo.SignatureMethod);
            if (signatureProvider == null)
                throw LogValidationException(LogMessages.IDX30203, cryptoProviderFactory, key, SignedInfo.SignatureMethod);

            try
            {
                using (var memoryStream = new MemoryStream())
                {
                    SignedInfo.GetCanonicalBytes(memoryStream);
                    if (!signatureProvider.Verify(memoryStream.ToArray(), Convert.FromBase64String(SignatureValue)))
                        throw LogValidationException(LogMessages.IDX30200, cryptoProviderFactory, key);
                }

                SignedInfo.Verify(cryptoProviderFactory);
            }
            finally
            {
                if (signatureProvider != null)
                    cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

#nullable enable
        internal SignatureValidationError? Verify(
            SecurityKey key,
            CryptoProviderFactory cryptoProviderFactory,
#pragma warning disable CA1801 // Review unused parameters
            CallContext callContext)
#pragma warning restore CA1801
        {
            if (key is null)
                return SignatureValidationError.NullParameter(
                    nameof(key),
                    ValidationError.GetCurrentStackFrame());

            if (cryptoProviderFactory is null)
                return SignatureValidationError.NullParameter(
                    nameof(cryptoProviderFactory),
                    ValidationError.GetCurrentStackFrame());

            if (SignedInfo is null)
                return new SignatureValidationError(
                    new MessageDetail(LogMessages.IDX30212),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenInvalidSignatureException),
                    ValidationError.GetCurrentStackFrame());

            if (!cryptoProviderFactory.IsSupportedAlgorithm(SignedInfo.SignatureMethod, key))
                return new SignatureValidationError(
                    new MessageDetail(LogMessages.IDX30207, SignedInfo.SignatureMethod, cryptoProviderFactory.GetType()),
                    ValidationFailureType.XmlValidationFailed,
                    typeof(SecurityTokenInvalidSignatureException),
                    ValidationError.GetCurrentStackFrame());

            var signatureProvider = cryptoProviderFactory.CreateForVerifying(key, SignedInfo.SignatureMethod);
            if (signatureProvider is null)
                return new SignatureValidationError(
                    new MessageDetail(LogMessages.IDX30203, cryptoProviderFactory, key, SignedInfo.SignatureMethod),
                    ValidationFailureType.XmlValidationFailed,
                    typeof(SecurityTokenInvalidSignatureException),
                    ValidationError.GetCurrentStackFrame());

            SignatureValidationError? validationError = null;

            try
            {
                using (var memoryStream = new MemoryStream())
                {
                    SignedInfo.GetCanonicalBytes(memoryStream);
                    if (!signatureProvider.Verify(memoryStream.ToArray(), Convert.FromBase64String(SignatureValue)))
                    {
                        validationError = new SignatureValidationError(
                            new MessageDetail(LogMessages.IDX30200, cryptoProviderFactory, key),
                            ValidationFailureType.XmlValidationFailed,
                            typeof(SecurityTokenInvalidSignatureException),
                            ValidationError.GetCurrentStackFrame());
                    }
                }

                if (validationError is null)
                {
                    validationError = SignedInfo.Verify(cryptoProviderFactory, callContext);
                    validationError?.AddCurrentStackFrame();
                }
            }
            finally
            {
                if (signatureProvider is not null)
                    cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }

            if (validationError is not null)
                return validationError;

            return null; // no error
        }
#nullable restore
    }
}
