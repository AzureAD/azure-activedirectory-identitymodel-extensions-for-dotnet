// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

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
            // TODO - brentsch, need tests for DSA
            if (certificate == null)
                throw new ArgumentNullException("certificate");

            _certificate = certificate;
        }

        public override int KeySize
        {
            get { return PublicKey.Key.KeySize; }
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
                            _privateKey = _certificate.PrivateKey;
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
            if (string.IsNullOrWhiteSpace("algorithm"))
                throw new ArgumentNullException("algorithm");

            if (verifyOnly)
                return SignatureProviderFactory.CreateForVerifying(this, algorithm);
            else
                return SignatureProviderFactory.CreateForSigning(this, algorithm);
        }

        //public HashAlgorithm GetHashAlgorithmForSignature(string algorithm)
        //{
        //    if (string.IsNullOrEmpty(algorithm))
        //        throw new ArgumentNullException("algorithm");

        //    switch (algorithm)
        //    {
        //        case SecurityAlgorithms.RsaSha1Signature:
        //            return SHA1.Create();
        //        case SecurityAlgorithms.RsaSha256Signature:
        //            return SHA256.Create();
        //        default:
        //            throw new CryptographicException("UnsupportedAlgorithmForCryptoOperation: " + algorithm);
        //    }
        //}

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
