//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    using System.Security.Cryptography;

    sealed public class RsaSecurityKey : AsymmetricSecurityKey
    {
        PrivateKeyStatus privateKeyStatus = PrivateKeyStatus.AvailabilityNotDetermined;
        readonly RSA rsa;

        public RsaSecurityKey(RSA rsa)
        {
            if (rsa == null)
                throw new ArgumentNullException("rsa");

            this.rsa = rsa;
        }

        public override int KeySize
        {
            get { return this.rsa.KeySize; }
        }

        public override AsymmetricAlgorithm GetAsymmetricAlgorithm(string algorithm, bool requiresPrivateKey)
        {
            if (requiresPrivateKey && !HasPrivateKey())
            {
                throw new CryptographicException("NoPrivateKeyAvailable");
            }

            return this.rsa;
        }

        public override HashAlgorithm GetHashAlgorithmForSignature(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentNullException("algorithm");
            }

            // TODO - brentsch - introduce Creation
            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha1Signature:
                    return SHA1.Create();
                case SecurityAlgorithms.RsaSha256Signature:
                    return SHA256.Create();
                default:
                    throw new CryptographicException("UnsupportedAlgorithmForCryptoOperation: " + algorithm);
            }
        }

            //public override AsymmetricSignatureDeformatter GetSignatureDeformatter(string algorithm)
            //{
            //    if (string.IsNullOrEmpty(algorithm))
            //    {
            //        throw new ArgumentNullException("algorithm");
            //    }

            //    switch (algorithm)
            //    {
            //        case SecurityAlgorithms.RsaSha1Signature:
            //        case SecurityAlgorithms.RsaSha256Signature:
            //            return new RSAPKCS1SignatureDeformatter(rsa);
            //        default:
            //            throw new CryptographicException("UnsupportedAlgorithmForCryptoOperation: " + algorithm);
            //    }
            //}

            //public override AsymmetricSignatureFormatter GetSignatureFormatter(string algorithm)
            //{
            //    if (string.IsNullOrEmpty(algorithm))
            //    {
            //        throw new ArgumentNullException("algorithm");
            //    }

            //    switch (algorithm)
            //    {
            //        case SecurityAlgorithms.RsaSha1Signature:
            //        case SecurityAlgorithms.RsaSha256Signature:
            //            // Ensure that we have an RSA algorithm object.
            //            return new RSAPKCS1SignatureFormatter(this.rsa);
            //        default:
            //            throw new CryptographicException("UnsupportedAlgorithmForCryptoOperation: " + algorithm);
            //    }
            //}

        public override bool HasPrivateKey()
        {
            if (this.privateKeyStatus == PrivateKeyStatus.AvailabilityNotDetermined)
            {
                RSACryptoServiceProvider rsaCryptoServiceProvider = this.rsa as RSACryptoServiceProvider;
                if (rsaCryptoServiceProvider != null)
                {
                    this.privateKeyStatus = rsaCryptoServiceProvider.PublicOnly ? PrivateKeyStatus.DoesNotHavePrivateKey : PrivateKeyStatus.HasPrivateKey;
                }
                else
                {
                    try
                    {
                        byte[] hash = new byte[20];
                        this.rsa.DecryptValue(hash); // imitate signing
                        this.privateKeyStatus = PrivateKeyStatus.HasPrivateKey;
                    }
                    catch (CryptographicException)
                    {
                        this.privateKeyStatus = PrivateKeyStatus.DoesNotHavePrivateKey;
                    }
                }
            }
            return this.privateKeyStatus == PrivateKeyStatus.HasPrivateKey;
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentNullException("algorithm");
            }

            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha1Signature:
                case SecurityAlgorithms.RsaSha256Signature:
                    return true;
                default:
                    return false;
            }
        }

        enum PrivateKeyStatus
        {
            AvailabilityNotDetermined,
            HasPrivateKey,
            DoesNotHavePrivateKey
        }
    }
}
