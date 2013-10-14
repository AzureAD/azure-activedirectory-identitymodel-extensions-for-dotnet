// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Provides signing and verifying operations using a <see cref="SymmetricSecurityKey"/> and specifying an algorithm.
    /// </summary>
    public class SymmetricSignatureProvider : SignatureProvider
    {

        private static byte[] _bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
        private static byte[] _bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
        private bool _disposed;
        private KeyedHashAlgorithm _keyedHash;

        /// <summary>
        /// Creates an instance of a signature provider that uses an <see cref="SymmetricSecurityKey"/> to create and / or verify signatures over a array of bytes.
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
        public SymmetricSignatureProvider( SymmetricSecurityKey key, string algorithm )
        {
            if ( key == null )
            {
                throw new ArgumentNullException( "key" );
            }

            if ( null == algorithm )
            {
                throw new ArgumentNullException( algorithm );
            }

            if ( string.IsNullOrWhiteSpace( algorithm ) )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, WifExtensionsErrors.WIF10002, "algorithm" ) );
            }

            if ( key.KeySize < SignatureProviderFactory.MinimumSymmetricKeySizeInBits )
            {
                throw new ArgumentOutOfRangeException( "key.KeySize", key.KeySize, string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10503, key.GetType(), SignatureProviderFactory.MinimumSymmetricKeySizeInBits ) );
            }

            try
            {
                _keyedHash = key.GetKeyedHashAlgorithm( algorithm );
            }
            catch ( Exception ex )
            {
                if ( DiagnosticUtility.IsFatal( ex ) )
                {
                    throw;
                }

                throw new InvalidOperationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10532, algorithm, key.ToString(), ex ), ex );
            }

            if ( _keyedHash == null )
            {
                throw new InvalidOperationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10533, algorithm, key.ToString() ) );
            }

            try
            {
                _keyedHash.Key = key.GetSymmetricKey();
            }
            catch ( Exception ex )
            {
                if ( DiagnosticUtility.IsFatal( ex ) )
                {
                    throw;
                }

                throw new InvalidOperationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10534, algorithm, key.ToString(), ex ), ex );
            }

        }

        #region IDisposable Members

        /// <summary>
        /// Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/>
        /// </summary>
        public override void Dispose()
        {
            Dispose( true );
            GC.SuppressFinalize( this );
        }

        /// <summary>
        /// Disposes of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose( bool disposing )
        {
            if ( !_disposed )
            {
                if ( disposing )
                {
                    if ( _keyedHash != null )
                    {
                        _keyedHash.Dispose();
                        _keyedHash = null;
                    }
                }

                _disposed = true;
            }
        }

        #endregion

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="SymmetricSecurityKey"/> and 'algorithm' passed to <see cref="SymmetricSignatureProvider( SymmetricSecurityKey, string )"/>.
        /// </summary>
        /// <param name="input">bytes to sign.</param>
        /// <returns>signed bytes</returns>
        /// <exception cref="ArgumentNullException">'input' is null. </exception>
        /// <exception cref="ArgumentException">'input.Length' == 0. </exception>
        /// <exception cref="ObjectDisposedException"><see cref="Dispose(bool)"/> has been called.</exception>
        /// <exception cref="InvalidOperationException"><see cref="KeyedHashAlgorithm"/> is null. This can occur if a derived type deletes it or does not create it.</exception>
        public override byte[] Sign( byte[] input )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( "input" );
            }

            if ( input.Length == 0 )
            {
                throw new ArgumentException( JwtErrors.Jwt10524 );
            }

            if ( _disposed )
            {
                throw new ObjectDisposedException( typeof( SymmetricSignatureProvider ).ToString() );
            }

            if ( _keyedHash == null )
            {
                throw new InvalidOperationException( JwtErrors.Jwt10523 );
            }

            return _keyedHash.ComputeHash( input );
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
        public override bool Verify( byte[] input, byte[] signature )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( "input" );
            }

            if ( signature == null )
            {
                throw new ArgumentNullException( "signature" );
            }

            if ( input.Length == 0 )
            {
                throw new ArgumentException( JwtErrors.Jwt10525 );
            }

            if ( signature.Length == 0 )
            {
                throw new ArgumentException( JwtErrors.Jwt10526 );
            }

            if ( _disposed )
            {
                throw new ObjectDisposedException( typeof( SymmetricSignatureProvider ).ToString() );
            }

            if ( _keyedHash == null )
            {
                throw new InvalidOperationException( JwtErrors.Jwt10523 );
            }

            return AreEqual( signature, _keyedHash.ComputeHash( input ) );
        }

        /// <summary>
        /// Compares two byte arrays for equality. Hash size is fixed normally it is 32 bytes.
        /// The attempt here is to take the same time if an attacker shortens the signature OR changes some of the signed contents.
        /// </summary>
        [MethodImpl( MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining )]
        private static bool AreEqual( byte[] a, byte[] b )
        {
            Int32 result = 0;
            byte[] a1, a2;

            if ( ( ( null == a ) || ( null == b ) )
            || ( a.Length != b.Length ) )
            {
                a1 = _bytesA; a2 = _bytesB;
            }
            else
            {
                a1 = a; a2 = b;
            }

            for ( int i = 0; i < a.Length; i++ )
            {
                result |= a1[i] ^ a2[i];
            }

            return result == 0;
        }
    }
}
