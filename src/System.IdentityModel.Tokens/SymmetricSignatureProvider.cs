//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
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
//-----------------------------------------------------------------------

using System.Diagnostics.Tracing;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Provides signing and verifying operations using a <see cref="SymmetricSecurityKey"/> and specifying an algorithm.
    /// </summary>
    public class SymmetricSignatureProvider : SignatureProvider
    {
        private static byte[] bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
        private static byte[] bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
        private bool disposed;
        private KeyedHashAlgorithm keyedHash;

        /// <summary>
        /// This is the minimum <see cref="SymmetricSecurityKey"/>.KeySize when creating and verifying signatures.
        /// </summary>
        public static readonly int DefaultMinimumSymmetricKeySizeInBits = 128;

        private int minimumSymmetricKeySizeInBits = DefaultMinimumSymmetricKeySizeInBits;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricSignatureProvider"/> class that uses an <see cref="SymmetricSecurityKey"/> to create and / or verify signatures over a array of bytes.
        /// </summary>
        /// <param name="key">The <see cref="SymmetricSecurityKey"/> used for signing.</param>
        /// <param name="algorithm">The signature algorithm to use.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null.</exception>
        /// <exception cref="ArgumentException">'algorithm' contains only whitespace.</exception>
        /// <exception cref="ArgumentOutOfRangeException">'<see cref="SymmetricSecurityKey"/>.KeySize' is smaller than <see cref="SignatureProviderFactory.MinimumSymmetricKeySizeInBits"/>.</exception>
        /// <exception cref="InvalidOperationException"><see cref="SymmetricSecurityKey.GetKeyedHashAlgorithm"/> throws.</exception>
        /// <exception cref="InvalidOperationException"><see cref="SymmetricSecurityKey.GetKeyedHashAlgorithm"/> returns null.</exception>
        /// <exception cref="InvalidOperationException"><see cref="SymmetricSecurityKey.GetSymmetricKey"/> throws.</exception>
        public SymmetricSignatureProvider(SymmetricSecurityKey key, string algorithm)
        {
            if (key == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": key"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (!IsSupportedAlgorithm(algorithm))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm ?? "null"), typeof(InvalidOperationException), EventLevel.Error);
            }

            if (key.KeySize < MinimumSymmetricKeySizeInBits)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10603, key.GetType(), MinimumSymmetricKeySizeInBits + ", KeySize: " + key.KeySize), typeof(ArgumentOutOfRangeException), EventLevel.Error);
            }

            this.keyedHash = GetKeyedHashAlgorithm(algorithm);

            try
            {
                this.keyedHash.Key = key.Key;
            }
            catch (Exception ex)
            {
                if (DiagnosticUtility.IsFatal(ex))
                {
                    throw;
                }

                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10634, algorithm, key, ex), typeof(InvalidOperationException), EventLevel.Error);
            }
        }

        /// <summary>
        /// Gets or sets the minimum <see cref="SymmetricSecurityKey"/>.KeySize"/>.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' is smaller than <see cref="AbsoluteMinimumSymmetricKeySizeInBits"/>.</exception>
        public int MinimumSymmetricKeySizeInBits
        {
            get
            {
                return minimumSymmetricKeySizeInBits;
            }

            set
            {
                if (value < DefaultMinimumSymmetricKeySizeInBits)
                {
                    throw new ArgumentOutOfRangeException("value", value, string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10628, DefaultMinimumSymmetricKeySizeInBits));
                }

                minimumSymmetricKeySizeInBits = value;
            }
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            return false;
        }

        protected virtual KeyedHashAlgorithm GetKeyedHashAlgorithm(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": algorithm"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            switch (algorithm)
            {
                default:
                    {
                        LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm), typeof(ArgumentOutOfRangeException), EventLevel.Error);
                        return null;
                    }
            }
        }

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="SymmetricSecurityKey"/> and 'algorithm' passed to <see cref="SymmetricSignatureProvider( SymmetricSecurityKey, string )"/>.
        /// </summary>
        /// <param name="input">bytes to sign.</param>
        /// <returns>signed bytes</returns>
        /// <exception cref="ArgumentNullException">'input' is null. </exception>
        /// <exception cref="ArgumentException">'input.Length' == 0. </exception>
        /// <exception cref="ObjectDisposedException"><see cref="Dispose(bool)"/> has been called.</exception>
        /// <exception cref="InvalidOperationException"><see cref="KeyedHashAlgorithm"/> is null. This can occur if a derived type deletes it or does not create it.</exception>
        public override byte[] Sign(byte[] input)
        {
            if (input == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": input"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (input.Length == 0)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10624), typeof(ArgumentException), EventLevel.Error);
            }

            if (this.disposed)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, typeof(SymmetricSignatureProvider).ToString()), typeof(ObjectDisposedException), EventLevel.Error);
            }

            if (this.keyedHash == null)
            {
                LogHelper.Throw(LogMessages.IDX10623, typeof(InvalidOperationException), EventLevel.Error);
            }

            IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10642, input.ToString()));
            return this.keyedHash.ComputeHash(input);
        }

        /// <summary>
        /// Verifies that a signature created over the 'input' matches the signature. Using <see cref="SymmetricSecurityKey"/> and 'algorithm' passed to <see cref="SymmetricSignatureProvider( SymmetricSecurityKey, string )"/>.
        /// </summary>
        /// <param name="input">bytes to verify.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <returns>true if computed signature matches the signature parameter, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">'input' is null.</exception>
        /// <exception cref="ArgumentNullException">'signature' is null.</exception>
        /// <exception cref="ArgumentException">'input.Length' == 0.</exception>
        /// <exception cref="ArgumentException">'signature.Length' == 0. </exception>
        /// <exception cref="ObjectDisposedException"><see cref="Dispose(bool)"/> has been called.</exception>
        /// <exception cref="InvalidOperationException">if the internal <see cref="KeyedHashAlgorithm"/> is null. This can occur if a derived type deletes it or does not create it.</exception>
        public override bool Verify(byte[] input, byte[] signature)
        {
            if (input == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": input"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (signature == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": signature"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (input.Length == 0)
            {
                LogHelper.Throw(LogMessages.IDX10625, typeof(ArgumentException), EventLevel.Error);
            }

            if (signature.Length == 0)
            {
                LogHelper.Throw(LogMessages.IDX10626, typeof(ArgumentException), EventLevel.Error);
            }

            if (this.disposed)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, typeof(SymmetricSignatureProvider).ToString()), typeof(ObjectDisposedException), EventLevel.Error);
            }

            if (this.keyedHash == null)
            {
                LogHelper.Throw(LogMessages.IDX10623, typeof(InvalidOperationException), EventLevel.Error);
            }

            IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10643, input.ToString()));
            return AreEqual(signature, this.keyedHash.ComputeHash(input));
        }

        #region IDisposable Members

        /// <summary>
        /// Disposes of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                this.disposed = true;

                if (disposing)
                {
                    if (this.keyedHash != null)
                    {
                        this.keyedHash.Dispose();
                        this.keyedHash = null;
                    }
                }
            }
        }

        #endregion

        /// <summary>
        /// Compares two byte arrays for equality. Hash size is fixed normally it is 32 bytes.
        /// The attempt here is to take the same time if an attacker shortens the signature OR changes some of the signed contents.
        /// </summary>
        /// <param name="a">
        /// One set of bytes to compare.
        /// </param>
        /// <param name="b">
        /// The other set of bytes to compare with.
        /// </param>
        /// <returns>
        /// true if the bytes are equal, false otherwise.
        /// </returns>
        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static bool AreEqual(byte[] a, byte[] b)
        {
            int result = 0;
            byte[] a1, a2;

            if (((null == a) || (null == b))
            || (a.Length != b.Length))
            {
                a1 = bytesA; 
                a2 = bytesB;
            }
            else
            {
                a1 = a; 
                a2 = b;
            }

            for (int i = 0; i < a1.Length; i++)
            {
                result |= a1[i] ^ a2[i];
            }

            return result == 0;
        }
    }
}
