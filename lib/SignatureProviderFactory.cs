//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Globalization;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Creates <see cref="SignatureProvider"/>s by specifying a <see cref="SecurityKey"/> and algorithm.
    /// <para>Supports both <see cref="AsymmetricSecurityKey"/> and <see cref="SymmetricSecurityKey"/>.</para>
    /// </summary>
    public class SignatureProviderFactory
    {
        /// <summary>
        /// This is the minimum <see cref="AsymmetricSecurityKey"/>.KeySize when creating signatures.
        /// </summary>
        public static readonly uint AbsoluteMinimumAsymmetricKeySizeInBitsForSigning = 2048;

        /// <summary>
        /// This is the minimum <see cref="AsymmetricSecurityKey"/>.KeySize when verifying signatures.
        /// </summary>
        public static readonly uint AbsoluteMinimumAsymmetricKeySizeInBitsForVerfying = 1024;

        /// <summary>
        /// This is the minimum <see cref="SymmetricSecurityKey"/>.KeySize when creating and verifying signatures.
        /// </summary>
        public static readonly uint AbsoluteMinimumSymmetricKeySizeInBits = 128;

        private static uint _minimumAsymmetricKeySizeInBitsForSigning = AbsoluteMinimumAsymmetricKeySizeInBitsForSigning;
        private static uint _minimumAsymmetricKeySizeInBitsForVerfying = AbsoluteMinimumAsymmetricKeySizeInBitsForVerfying;
        private static uint _minimumSymmetricKeySizeInBits = AbsoluteMinimumSymmetricKeySizeInBits;

        /// <summary>
        /// Creates a <see cref="SignatureProvider"/> that supports the <see cref="SecurityKey"/> and algorithm.
        /// </summary>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null.</exception>
        /// <exception cref="ArgumentException">'algorithm' contains only whitespace.</exception>
        /// <exception cref="ArgumentOutOfRangeException">'<see cref="AsymmetricSecurityKey"/>' is smaller than <see cref="MinimumAsymmetricKeySizeInBitsForSigning"/>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">'<see cref="SymmetricSecurityKey"/>' is smaller than <see cref="MinimumSymmetricKeySizeInBits"/>.</exception>
        /// <exception cref="ArgumentException">'<see cref="SecurityKey"/>' is not a <see cref="AsymmetricSecurityKey"/> or a <see cref="SymmetricSecurityKey"/>.</exception>
        /// <remarks>AsymmetricSignatureProviders require access to a PrivateKey for Signing.</remarks>
        public virtual SignatureProvider CreateForSigning( SecurityKey key, string algorithm )
        {
            return CreateProvider( key, algorithm, true );
        }

        /// <summary>
        /// Returns a <see cref="SignatureProvider"/> instance supports the <see cref="SecurityKey"/> and algorithm.
        /// </summary>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null.</exception>
        /// <exception cref="ArgumentException">'algorithm' contains only whitespace.</exception>
        /// <exception cref="ArgumentOutOfRangeException">'<see cref="AsymmetricSecurityKey"/>' is smaller than <see cref="MinimumAsymmetricKeySizeInBitsForVerifying"/>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">'<see cref="SymmetricSecurityKey"/>' is smaller than <see cref="MinimumSymmetricKeySizeInBits"/>.</exception>
        /// <exception cref="ArgumentException">'<see cref="SecurityKey"/>' is not a <see cref="AsymmetricSecurityKey"/> or a <see cref="SymmetricSecurityKey"/>.</exception>
        public virtual SignatureProvider CreateForVerifying( SecurityKey key, string algorithm )
        {
           return CreateProvider( key, algorithm, false );
        }

        private SignatureProvider CreateProvider( SecurityKey key, string algorithm, bool willCreateSignatures )
        {
            if ( key == null )
            {
                throw new ArgumentNullException( "key" );
            }

            if ( algorithm == null )
            {
                throw new ArgumentException( "algorithm" );
            }

            if ( string.IsNullOrWhiteSpace( algorithm ) )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, WifExtensionsErrors.WIF10002, "algorithm " ) );
            }

            AsymmetricSecurityKey asymmetricKey = key as AsymmetricSecurityKey;
            if ( asymmetricKey != null )
            {
                if ( willCreateSignatures )
                {
                    if ( asymmetricKey.KeySize < MinimumAsymmetricKeySizeInBitsForSigning )
                    {
                        throw new ArgumentOutOfRangeException( "key.KeySize", asymmetricKey.KeySize, string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10530, key.GetType(), MinimumAsymmetricKeySizeInBitsForSigning ) );
                    }

                }
                
                if ( asymmetricKey.KeySize < MinimumAsymmetricKeySizeInBitsForVerifying )
                {
                    throw new ArgumentOutOfRangeException( "key.KeySize", asymmetricKey.KeySize, string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10531, key.GetType(), MinimumAsymmetricKeySizeInBitsForVerifying ) );
                }

                return new AsymmetricSignatureProvider( asymmetricKey, algorithm, willCreateSignatures );
            }

            SymmetricSecurityKey symmetricKey = key as SymmetricSecurityKey;
            if ( symmetricKey != null )
            {
                if ( symmetricKey.KeySize < MinimumSymmetricKeySizeInBits )
                {
                    throw new ArgumentOutOfRangeException( "key.KeySize", key.KeySize, string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10503, key.GetType(), MinimumSymmetricKeySizeInBits ) );
                }

                return new SymmetricSignatureProvider( symmetricKey, algorithm );
            }

            throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10500, typeof(SignatureProvider).ToString(), typeof( SecurityKey ), typeof( AsymmetricSecurityKey ), typeof( SymmetricSecurityKey ), key.GetType() ) );
        }

        /// <summary>
        /// Gets or sets the minimum <see cref="SymmetricSecurityKey"/>.KeySize"/>.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' is smaller than <see cref="AbsoluteMinimumSymmetricKeySizeInBits"/>.</exception>
        public static uint MinimumSymmetricKeySizeInBits
        {
            get 
            { 
                return _minimumSymmetricKeySizeInBits; 
            }

            set
            {
                if ( value < AbsoluteMinimumSymmetricKeySizeInBits )
                {
                    throw new ArgumentOutOfRangeException( "value", value, string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10528, AbsoluteMinimumSymmetricKeySizeInBits ) );
                }

                _minimumSymmetricKeySizeInBits = value;
            }
        }

        /// <summary>
        /// Gets or sets the minimum <see cref="AsymmetricSecurityKey"/>.KeySize for creating signatures.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' is smaller than <see cref="AbsoluteMinimumAsymmetricKeySizeInBitsForSigning"/>.</exception>
        public static uint MinimumAsymmetricKeySizeInBitsForSigning
        {
            get 
            { 
                return _minimumAsymmetricKeySizeInBitsForSigning; 
            }

            set
            {
                if ( value < AbsoluteMinimumAsymmetricKeySizeInBitsForSigning )
                {
                    throw new ArgumentOutOfRangeException("value", value, string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10513, AbsoluteMinimumAsymmetricKeySizeInBitsForSigning ) );
                }

                _minimumAsymmetricKeySizeInBitsForSigning = value;
            }
        }

        /// <summary>
        /// Gets or sets the minimum <see cref="AsymmetricSecurityKey"/>.KeySize for verifying signatures.
        /// <exception cref="ArgumentOutOfRangeException">'value' is smaller than <see cref="AbsoluteMinimumAsymmetricKeySizeInBitsForVerfying"/>.</exception>
        /// </summary>
        public static uint MinimumAsymmetricKeySizeInBitsForVerifying
        {
            get 
            { 
                return _minimumAsymmetricKeySizeInBitsForVerfying; 
            }

            set
            {
                if ( value < AbsoluteMinimumAsymmetricKeySizeInBitsForVerfying )
                {
                    throw new ArgumentOutOfRangeException( "value", value, string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10527, AbsoluteMinimumAsymmetricKeySizeInBitsForVerfying ) );
                }

                _minimumAsymmetricKeySizeInBitsForVerfying = value;
            }
        }

        /// <summary>
        /// When finished with a <see cref="SignatureProvider"/> call this method for cleanup. The default behavior is to call <see cref="SignatureProvider.Dispose"/>
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to be released.</param>
        public virtual void ReleaseProvider( SignatureProvider signatureProvider )
        {
            if ( signatureProvider != null )
            {
                signatureProvider.Dispose();
            }
        }
    }
}