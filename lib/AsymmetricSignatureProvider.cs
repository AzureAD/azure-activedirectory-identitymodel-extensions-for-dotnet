//-----------------------------------------------------------------------
// <copyright file="AsymmetricSignatureProvider.cs" company="Microsoft">Copyright 2012 Microsoft Corporation</copyright>
// <license>
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// </license>

namespace System.IdentityModel.Tokens
{
    using System.Globalization;
    using System.Security.Cryptography;

    /// <summary>
    /// Provides signing and verifying operations when working with an <see cref="AsymmetricSecurityKey"/>
    /// </summary>
    public class AsymmetricSignatureProvider : SignatureProvider
    {
        private bool _disposed;
        private HashAlgorithm _hash;
        private AsymmetricSignatureFormatter _formatter;
        private AsymmetricSignatureDeformatter _deformatter;
        private AsymmetricSecurityKey _key;

        /// <summary>
        /// Initializes a new instance of <see cref="AsymmetricSignatureProvider"/> to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="AsymmetricSecurityKey"/> that will be used for cryptographic operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <param name="willCreateSignatures">If this <see cref="AsymmetricSignatureProvider"/> is required to create signatures then set this to true.
        /// <para>Creating signatures requires that the <see cref="AsymmetricSecurityKey"/> has access to a private key. 
        /// Verifying signatures (the default), does not require access to the private key.</para></param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null.</exception>
        /// <exception cref="ArgumentException">'algorithm' contains only whitespace.</exception>
        /// <exception cref="ArgumentOutOfRangeException">willCreateSignatures is true and <see cref="AsymmetricSecurityKey"/>.KeySize is less than <see cref="SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForSigning"/>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="AsymmetricSecurityKey"/>.KeySize is less than <see cref="SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying"/>. Note: this is always checked.</exception>
        /// <exception cref="InvalidOperationException">Is thrown if the <see cref="AsymmetricSecurityKey.GetHashAlgorithmForSignature"/> throws.</exception> 
        /// <exception cref="InvalidOperationException">Is thrown if the <see cref="AsymmetricSecurityKey.GetHashAlgorithmForSignature"/> returns null.</exception>
        /// <exception cref="InvalidOperationException">Is thrown if the <see cref="AsymmetricSecurityKey.GetSignatureFormatter"/> throws.</exception>         
        /// <exception cref="InvalidOperationException">Is thrown if the <see cref="AsymmetricSecurityKey.GetSignatureFormatter"/> returns null.</exception>         
        /// <exception cref="InvalidOperationException">Is thrown if the <see cref="AsymmetricSecurityKey.GetSignatureDeformatter"/> throws.</exception>         
        /// <exception cref="InvalidOperationException">Is thrown if the <see cref="AsymmetricSecurityKey.GetSignatureDeformatter"/> returns null.</exception>         
        /// <exception cref="InvalidOperationException">Is thrown if the <see cref="AsymmetricSignatureFormatter.SetHashAlgorithm"/> throws.</exception>         
        /// <exception cref="InvalidOperationException">Is thrown if the <see cref="AsymmetricSignatureDeformatter.SetHashAlgorithm"/> throws.</exception>         
        public AsymmetricSignatureProvider(AsymmetricSecurityKey key, string algorithm, bool willCreateSignatures = false)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }

            if (string.IsNullOrWhiteSpace(algorithm))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, WifExtensionsErrors.WIF10002, "algorithm"));
            }

            if (willCreateSignatures)
            {
                if (key.KeySize < SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForSigning)
                {
                    throw new ArgumentOutOfRangeException("key.KeySize", key.KeySize, string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10531, key.GetType(), SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForSigning));
                }
            }

            if (key.KeySize < SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying)
            {
                throw new ArgumentOutOfRangeException("key.KeySize", key.KeySize, string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10530, key.GetType(), SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying));
            }

            this._key = key;
            try
            {
                this._hash = this._key.GetHashAlgorithmForSignature(algorithm);
            }
            catch (Exception ex)
            {
                if (DiagnosticUtility.IsFatal(ex))
                {
                    throw;
                }

                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10518, algorithm, this._key.ToString(), ex), ex);
            }

            if (this._hash == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10511, algorithm, this._key.ToString()));
            }

            if (willCreateSignatures)
            {
                try
                {
                    this._formatter = this._key.GetSignatureFormatter(algorithm);
                    this._formatter.SetHashAlgorithm(this._hash.GetType().ToString());
                }
                catch (Exception ex)
                {
                    if (DiagnosticUtility.IsFatal(ex))
                    {
                        throw;
                    }

                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10514, algorithm, this._key.ToString(), ex), ex);
                }

                if (this._formatter == null)
                {
                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10515, algorithm, this._key.ToString()));
                }
            }

            try
            {
                this._deformatter = this._key.GetSignatureDeformatter(algorithm);
                this._deformatter.SetHashAlgorithm(this._hash.GetType().ToString());
            }
            catch (Exception ex)
            {
                if (DiagnosticUtility.IsFatal(ex))
                {
                    throw;
                }

                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10516, algorithm, this._key.ToString(), ex), ex);
            }

            if (this._deformatter == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10517, algorithm, this._key.ToString()));
            }
        }

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="AsymmetricSecurityKey"/> and algorithm passed to <see cref="AsymmetricSignatureProvider( AsymmetricSecurityKey, string, bool )"/>.
        /// </summary>
        /// <param name="input">bytes to be signed.</param>
        /// <returns>a signature over the input.</returns>
        /// <exception cref="ArgumentNullException">'input' is null. </exception>
        /// <exception cref="ArgumentException">'input.Length' == 0. </exception>
        /// <exception cref="ObjectDisposedException">if <see cref="AsymmetricSignatureProvider.Dispose(bool)"/> has been called. </exception>
        /// <exception cref="InvalidOperationException">if the internal <see cref="AsymmetricSignatureFormatter"/> is null. This can occur if the constructor parameter 'willBeUsedforSigning' was not 'true'.</exception>
        /// <exception cref="InvalidOperationException">if the internal <see cref="HashAlgorithm"/> is null. This can occur if a derived type deletes it or does not create it.</exception>
        public override byte[] Sign(byte[] input)
        {
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }

            if (input.Length == 0)
            {
                throw new ArgumentException(JwtErrors.Jwt10524);
            }

            if (this._disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            if (this._formatter == null)
            {
                throw new InvalidOperationException(JwtErrors.Jwt10520);
            }

            if (this._hash == null)
            {
                throw new InvalidOperationException(JwtErrors.Jwt10521);
            }

            return this._formatter.CreateSignature(this._hash.ComputeHash(input));
        }

        /// <summary>
        /// Verifies that a signature over the' input' matches the signature.
        /// </summary>
        /// <param name="input">the bytes to generate the signature over.</param>
        /// <param name="signature">the value to verify against.</param>
        /// <returns>true if signature matches, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">'input' is null.</exception>
        /// <exception cref="ArgumentNullException">'signature' is null.</exception>
        /// <exception cref="ArgumentException">'input.Length' == 0.</exception>
        /// <exception cref="ArgumentException">'signature.Length' == 0.</exception>
        /// <exception cref="ObjectDisposedException">if <see cref="AsymmetricSignatureProvider.Dispose(bool)"/> has been called. </exception>
        /// <exception cref="InvalidOperationException">if the internal <see cref="AsymmetricSignatureDeformatter"/> is null. This can occur if a derived type does not call the base constructor.</exception>
        /// <exception cref="InvalidOperationException">if the internal <see cref="HashAlgorithm"/> is null. This can occur if a derived type deletes it or does not create it.</exception>
        public override bool Verify(byte[] input, byte[] signature)
        {
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }

            if (signature == null)
            {
                throw new ArgumentNullException("signature");
            }

            if (input.Length == 0)
            {
                throw new ArgumentException(JwtErrors.Jwt10525);
            }

            if (signature.Length == 0)
            {
                throw new ArgumentException(JwtErrors.Jwt10526);
            }

            if (this._disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            if (this._deformatter == null)
            {
                throw new InvalidOperationException(JwtErrors.Jwt10529);
            }

            if (this._hash == null)
            {
                throw new InvalidOperationException(JwtErrors.Jwt10521);
            }

            return this._deformatter.VerifySignature(this._hash.ComputeHash(input), signature);
        }

        /// <summary>
        /// Calls <see cref="HashAlgorithm.Dispose()"/> to release this managed resources.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!this._disposed)
            {
                if (disposing)
                {
                    this._disposed = true;

                    if (this._hash != null)
                    {
                        this._hash.Dispose();
                        this._hash = null;
                    }
                }
            }
        }
    }
}
