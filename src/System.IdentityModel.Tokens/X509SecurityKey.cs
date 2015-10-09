// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Diagnostics.Tracing;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Logging;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Security key that allows access to cert
    /// </summary>
    public class X509SecurityKey : AsymmetricSecurityKey
    {
        X509Certificate2    _certificate;
        AsymmetricAlgorithm _privateKey;
        bool                _privateKeyAvailabilityDetermined;
        PublicKey           _publicKey;
        object              _thisLock = new Object();

        /// <summary>
        /// Instantiates a <see cref="SecurityKey"/> using a <see cref="X509Certificate2"/>
        /// </summary>
        /// <param name="certificate"> cert to use.</param>
        public X509SecurityKey(X509Certificate2 certificate)
        { 
            if (certificate == null)
                throw new ArgumentNullException("certificate");

            _certificate = certificate;
			KeyId = certificate.Thumbprint;
        }

        public override int KeySize
        {
            get {
#if DNXCORE50
                return RSACertificateExtensions.GetRSAPublicKey(_certificate).KeySize;
#else
                return PublicKey.Key.KeySize;
#endif
            }
        }

        public AsymmetricAlgorithm PrivateKey
        {
            get
            {
                if (!_privateKeyAvailabilityDetermined)
                {
                    lock (ThisLock)
                    {
                        if (!_privateKeyAvailabilityDetermined)
                        {
#if DNXCORE50
                            _privateKey = RSACertificateExtensions.GetRSAPrivateKey(_certificate);
#else
                            _privateKey = _certificate.PrivateKey;
#endif
                            _privateKeyAvailabilityDetermined = true;
                        }
                    }
                }

                return _privateKey;
            }
        }

        public PublicKey PublicKey
        {
            get
            {
                if (_publicKey == null)
                {
                    lock (ThisLock)
                    {
                        if (_publicKey == null)
                        {
                            _publicKey = _certificate.PublicKey;
                        }
                    }
                }

                return _publicKey;
            }
        }

        Object ThisLock
        {
            get { return _thisLock; }
        }

        public override SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": algorithm"), typeof(ArgumentNullException), EventLevel.Verbose);

            if (verifyOnly)
                return SignatureProviderFactory.CreateForVerifying(this, algorithm);
            else
                return SignatureProviderFactory.CreateForSigning(this, algorithm);
        }

        public override bool HasPrivateKey
        {
            get
            {
                return (PrivateKey != null);
            }
        }

        public override bool HasPublicKey
        {
            get
            {
                return true;
            }
        }

        /// <summary>
        /// Gets the <see cref="X509Certificate2"/>.
        /// </summary>
        public X509Certificate2 Certificate
        {
            get
            {
                return 
                    _certificate;
            }
        }
    }
}
