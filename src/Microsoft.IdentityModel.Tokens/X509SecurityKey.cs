// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Logging;
#if NET9_0_OR_GREATER
using System.Threading;
#endif

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// An <see cref="AsymmetricSecurityKey"/> that is backed by a <see cref="X509Certificate2"/>
    /// </summary>
    public class X509SecurityKey : AsymmetricSecurityKey
    {
        // OID for RSA encryption
        // <see href="https://www.ietf.org/rfc/rfc3447"/> and <see href="https://www.ietf.org/rfc/rfc5698"/>
        const string RSAOid = "1.2.840.113549.1.1.1";

        // OID for ECDSA
        // <see href="https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.5"/> and <see href="https://datatracker.ietf.org/doc/html/rfc5480"/>
        const string ECDsaOid = "1.2.840.10045.2.1";

        AsymmetricAlgorithm _privateKey;
        AsymmetricAlgorithm _publicKey;
#if NET9_0_OR_GREATER
        Lock _thisLock = new();
#else
        object _thisLock = new();
#endif
        internal X509SecurityKey(JsonWebKey webKey)
            : base(webKey)
        {
            Certificate = CertificateHelper.LoadX509Certificate(webKey.X5c[0]);
            X5t = Base64UrlEncoder.Encode(Certificate.GetCertHash());
            webKey.ConvertedSecurityKey = this;
        }

        /// <summary>
        /// Instantiates a <see cref="X509SecurityKey"/> using a <see cref="X509Certificate2"/>
        /// </summary>
        /// <param name="certificate">The <see cref="X509Certificate2"/> to use.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="certificate"/> is null.</exception>
        public X509SecurityKey(X509Certificate2 certificate)
        {
            Certificate = certificate ?? throw LogHelper.LogArgumentNullException(nameof(certificate));
            KeyId = certificate.Thumbprint;
            X5t = Base64UrlEncoder.Encode(certificate.GetCertHash());
        }

        /// <summary>
        /// Instantiates a <see cref="X509SecurityKey"/> using a <see cref="X509Certificate2"/>.
        /// </summary>
        /// <param name="certificate">The <see cref="X509Certificate2"/> to use.</param>
        /// <param name="keyId">The value to set for the KeyId.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="certificate"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="keyId"/> is null or empty.</exception>
        public X509SecurityKey(X509Certificate2 certificate, string keyId)
        {
            Certificate = certificate ?? throw LogHelper.LogArgumentNullException(nameof(certificate));
            KeyId = string.IsNullOrEmpty(keyId) ? throw LogHelper.LogArgumentNullException(nameof(keyId)) : keyId;
            X5t = Base64UrlEncoder.Encode(certificate.GetCertHash());
        }

        /// <summary>
        /// Gets the key size.
        /// </summary>
        public override int KeySize
        {
            get => PublicKey.KeySize;
        }

        /// <summary>
        /// Gets the X5t of this <see cref="X509SecurityKey"/>.
        /// </summary>
        public string X5t { get; }

        /// <summary>
        /// Returns the private key from the <see cref="X509SecurityKey"/>.
        /// </summary>
        public AsymmetricAlgorithm PrivateKey
        {
            get
            {
                if (_privateKey == null)
                {
                    lock (ThisLock)
                    {
                        if (_privateKey == null)
                        {
                            switch (Certificate.PublicKey.Oid.Value)
                            {
                                case RSAOid:
                                    {
                                        _privateKey = Certificate.GetRSAPrivateKey();
                                        break;
                                    }
                                case ECDsaOid:
                                    {
                                        _privateKey = Certificate.GetECDsaPrivateKey();
                                        break;
                                    }
                            }
                        }
                    }
                }

                return _privateKey;
            }
        }

        /// <summary>
        /// Gets the public key from the <see cref="X509SecurityKey"/>.
        /// </summary>
        public AsymmetricAlgorithm PublicKey
        {
            get
            {
                if (_publicKey == null)
                {
                    lock (ThisLock)
                    {
                        if (_publicKey == null)
                        {
                            switch (Certificate.PublicKey.Oid.Value)
                            {
                                case RSAOid:
                                    {
                                        _publicKey = Certificate.GetRSAPublicKey();
                                        break;
                                    }
                                case ECDsaOid:
                                    {
                                        _publicKey = Certificate.GetECDsaPublicKey();
                                        break;
                                    }
                            }
                        }
                    }
                }

                return _publicKey;
            }
        }
#if NET9_0_OR_GREATER
        Lock ThisLock => _thisLock;
#else
        object ThisLock
        {
            get { return _thisLock; }
        }
#endif
        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus.")]
        public override bool HasPrivateKey
        {
            get { return PrivateKey != null; }
        }

        /// <summary>
        /// Gets an enum indicating if a private key exists.
        /// </summary>
        /// <return>'Exists' if private key exists for sure; 'DoesNotExist' if private key doesn't exist for sure; 'Unknown' if we cannot determine.</return>
        public override PrivateKeyStatus PrivateKeyStatus
        {
            get
            {
                return PrivateKey == null ? PrivateKeyStatus.DoesNotExist : PrivateKeyStatus.Exists;
            }
        }

        /// <summary>
        /// Gets the <see cref="X509Certificate2"/>.
        /// </summary>
        public X509Certificate2 Certificate
        {
            get; private set;
        }

        internal override string InternalId => X5t;


        /// <summary>
        /// Determines whether the <see cref="X509SecurityKey"/> can compute a JWK thumbprint.
        /// </summary>
        /// <returns><c>true</c> if JWK thumbprint can be computed; otherwise, <c>false</c>.</returns>
        /// <remarks>See: <see href="https://datatracker.ietf.org/doc/html/rfc7638"/></remarks>
        public override bool CanComputeJwkThumbprint()
        {
            return PublicKey is RSA || PublicKey is ECDsa;
        }

        /// <summary>
        /// Computes a sha256 hash over the <see cref="X509SecurityKey"/>.
        /// </summary>
        /// <returns>A JWK thumbprint.</returns>
        /// <remarks>See: <see href="https://datatracker.ietf.org/doc/html/rfc7638"/></remarks>
        public override byte[] ComputeJwkThumbprint()
        {
            return PublicKey is RSA ? new RsaSecurityKey(PublicKey as RSA).ComputeJwkThumbprint() : new ECDsaSecurityKey(PublicKey as ECDsa).ComputeJwkThumbprint();
        }

        /// <summary>
        /// Returns a bool indicating if this key is equivalent to another key.
        /// </summary>
        /// <return>true if the keys are equal; otherwise, false.</return>
        public override bool Equals(object obj)
        {
            if (!(obj is X509SecurityKey other))
                return false;

            return other.Certificate.Thumbprint.ToString() == Certificate.Thumbprint.ToString();
        }

        /// <summary>
        /// Returns an int hash code.
        /// </summary>
        /// <return>An int hash code</return>
        public override int GetHashCode()
        {
            return Certificate.GetHashCode();
        }
    }
}
