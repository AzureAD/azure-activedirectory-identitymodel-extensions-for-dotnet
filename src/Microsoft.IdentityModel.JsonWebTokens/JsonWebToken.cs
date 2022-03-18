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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

#if NET45
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using JsonClaimSet = Microsoft.IdentityModel.JsonWebTokens.JsonClaimSet45;
#else
using System.Text.Json;
#endif

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// A <see cref="SecurityToken"/> designed for representing a JSON Web Token (JWT). 
    /// </summary>
    public class JsonWebToken : SecurityToken, IClaimProvider, IJsonClaimSet
    {
        private char[] _hChars;
        private char[] _pChars;
        private char[] _sChars;

        private Lazy<string> _act;
        private Lazy<string> _alg;
        private Lazy<IEnumerable<string>> _audiences;
        private Lazy<string> _cty;
        private Lazy<string> _enc;
        private Lazy<string> _encodedHeader;
        private Lazy<string> _encodedPayload;
        private Lazy<string> _encodedSignature;
        private Lazy<DateTime> _iat;
        private Lazy<string> _id;
        private Lazy<string> _iss;
        private Lazy<string> _kid;
        private Lazy<string> _sub;
        private Lazy<string> _typ;
        private Lazy<DateTime> _validFrom;
        private Lazy<DateTime> _validTo;
        private Lazy<string> _x5t;
        private Lazy<string> _zip;
        //internal byte[] _ciphertextBytes;
        internal byte[] _initializationVectorBytes;
        //internal byte[] _authenticationTagBytes;
        internal byte[] _encodedHeaderAsciiBytes;
        internal byte[] _encryptedKeyBytes;

        /// <summary>
        /// Initializes a new instance of <see cref="JsonWebToken"/> from a string in JWS or JWE Compact serialized format.
        /// </summary>
        /// <param name="jwtEncodedString">A JSON Web Token that has been serialized in JWS or JWE Compact serialized format.</param>
        /// <exception cref="ArgumentNullException">'jwtEncodedString' is null or empty.</exception>
        /// <exception cref="ArgumentException">'jwtEncodedString' is not in JWS or JWE Compact serialization format.</exception>
        /// <remarks>
        /// see: https://datatracker.ietf.org/doc/html/rfc7519 (JWT)
        /// see: https://datatracker.ietf.org/doc/html/rfc7515 (JWS)
        /// see: https://datatracker.ietf.org/doc/html/rfc7516 (JWE)
        /// <para>
        /// The contents of the returned <see cref="JsonWebToken"/> have not been validated, the JSON Web Token is simply decoded. Validation can be accomplished using the validation methods in <see cref="JsonWebTokenHandler"/>
        /// </para>
        /// </remarks>
        public JsonWebToken(string jwtEncodedString)
        {
            if (string.IsNullOrEmpty(jwtEncodedString))
                throw new ArgumentNullException(nameof(jwtEncodedString));

            Initialize();
            ReadToken(jwtEncodedString);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JsonWebToken"/> class where the header contains the crypto algorithms applied to the encoded header and payload.
        /// </summary>
        /// <param name="header">A string containing JSON which represents the cryptographic operations applied to the JWT and optionally any additional properties of the JWT.</param>
        /// <param name="payload">A string containing JSON which represents the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }.</param>
        /// <remarks>
        /// see: https://datatracker.ietf.org/doc/html/rfc7519 (JWT)
        /// see: https://datatracker.ietf.org/doc/html/rfc7515 (JWS)
        /// see: https://datatracker.ietf.org/doc/html/rfc7516 (JWE)
        /// <para>
        /// The contents of the returned <see cref="JsonWebToken"/> have not been validated, the JSON Web Token is simply decoded. Validation can be accomplished using the validation methods in <see cref="JsonWebTokenHandler"/>
        /// </para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'header' is null.</exception>
        /// <exception cref="ArgumentNullException">'payload' is null.</exception>
        public JsonWebToken(string header, string payload)
        {
            if (string.IsNullOrEmpty(header))
                throw LogHelper.LogArgumentNullException(nameof(header));

            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            try
            {
                Header = new JsonClaimSet(header);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14301, header), ex));
            }

            try
            {
                Payload = new JsonClaimSet(payload);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14302, payload), ex));
            }

            Initialize();
        }

        /// <summary>
        /// Gets the AuthenticationTag from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// Contains the results of a Authentication Encryption with Associated Data (AEAD).
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-2
        /// <para>
        /// If this JWT is not encrypted with an algorithms that uses an Authentication Tag, an empty string will be returned.
        /// </para>
        /// </remarks>
        public string AuthenticationTag
        {
            // TODO - use lazy
            get
            {
                return AuthenticationTagBytes == null ? string.Empty : UTF8Encoding.UTF8.GetString(AuthenticationTagBytes);
            }
        }

        /// <summary>
        ///
        /// </summary>
        internal byte[] AuthenticationTagBytes
        {
            get;
            set;
        }

        /// <summary>
        /// Gets the Ciphertext representing the encrypted JWT in the original raw data.
        /// </summary>
        /// <remarks>
        /// When decrypted using values in the JWE header will contain the plaintext payload.
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-2
        /// <para>
        /// If this JWT is not encrypted, an empty string will be returned.
        /// </para>
        /// </remarks>
        public string Ciphertext
        {
            // TODO - use lazy
            get
            {
                return CipherTextBytes == null ? string.Empty : UTF8Encoding.UTF8.GetString(CipherTextBytes);
            }
        }

        /// <summary>
        ///
        /// </summary>
        internal byte[] CipherTextBytes
        {
            get;
            set;
        }

        /// <summary>
        /// Gets the EncodedHeader from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// The original Base64UrlEncoded string of the JWT header.
        /// </remarks>
        public string EncodedHeader => _encodedHeader.Value;

        /// <summary>
        /// Gets the Encrypted Content Encryption Key.
        /// </summary>
        /// <remarks>
        /// For some algorithms this value may be null even though the JWT was encrypted.
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-2
        /// <para>
        /// If not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string EncryptedKey { get; internal set; }

        internal byte[] EncryptedKeyBytes { get; set; }

        /// <summary>
        /// Gets the EncodedPayload from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// The original Base64UrlEncoded of the JWT payload.
        /// </remarks>
        public string EncodedPayload => _encodedPayload.Value;

        /// <summary>
        /// Gets the EncodedSignature from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// The original Base64UrlEncoded of the JWT signature.
        /// If the JWT was not signed, an empty string is returned.
        /// </remarks>
        public string EncodedSignature => _encodedSignature.Value;

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// The original Base64UrlEncoded of the JWT.
        /// </remarks>
        public string EncodedToken { get; private set; }

        internal bool HasPayloadClaim(string claimName)
        {
            return Payload.HasClaim(claimName);
        }

        internal JsonClaimSet Header { get; set; }

        internal byte[] HeaderAsciiBytes { get; set; }

        private void Initialize()
        {
            _act = new Lazy<string>(ActorFactory);
            _alg = new Lazy<string>(AlgFactory);
            _audiences = new Lazy<IEnumerable<string>>(AudiencesFactory);
            _cty = new Lazy<string>(CtyFactory);
            _enc = new Lazy<string>(EncFactory);
            _encodedHeader = new Lazy<string>(EncodedHeaderFactory);
            _encodedPayload = new Lazy<string>(EncodedPayloadFactory);
            _encodedSignature = new Lazy<string>(EncodedSignatureFactory);
            _iat = new Lazy<DateTime>(IatFactory);
            _id = new Lazy<string>(IdFactory);
            _iss = new Lazy<string>(IssuerFactory);
            _kid = new Lazy<string>(KidFactory);
            _sub = new Lazy<string>(SubFactory);
            _typ = new Lazy<string>(TypFactory);
            _validTo = new Lazy<DateTime>(ValidToFactory);
            _validFrom = new Lazy<DateTime>(ValidFromFactory);
            _x5t = new Lazy<string>(X5tFactory);
            _zip = new Lazy<string>(ZipFactory);
        }

        internal byte[] InitializationVectorBytes { get; set; }

        /// <summary>
        /// Gets the Initialization Vector used when encrypting the plaintext.
        /// </summary>
        /// <remarks>
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1.4
        /// <para>
        /// Some algorithms may not use an Initialization Vector.
        /// If not found an empty string is returned.
        /// </para>
        /// </remarks>
        public string InitializationVector { get; internal set; }

        /// <summary>
        /// Gets the <see cref="JsonWebToken"/> associated with this instance.
        /// </summary>
        /// <remarks>
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-2
        /// For encrypted tokens {JWE}, this represents the JWT that was encrypted.
        /// <para>
        /// If the JWT is not encrypted, this value will be null.
        /// </para>
        /// </remarks>
        public JsonWebToken InnerToken { get; internal set; }

        /// <summary>
        /// 
        /// </summary>
        public bool IsEncrypted { get => CipherTextBytes != null; }

        /// <summary>
        /// 
        /// </summary>
        public bool IsSigned { get; internal set; }

        /// <summary>
        ///
        /// </summary>
        internal JsonClaimSet Payload { get; set; }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override SecurityKey SecurityKey { get; }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that was used to sign this token.
        /// </summary>
        /// <remarks>
        /// If the JWT was not signed or validated, this value will be null.
        /// </remarks>
        public override SecurityKey SigningKey { get; set; }

        /// <summary>
        ///
        /// </summary>
        internal byte[] MessageBytes{ get; set; }

        private void ReadToken(string encodedJson)
        {
            List<int> dots = new List<int>();
            int index = 0;
            while (index < encodedJson.Length && dots.Count <= JwtConstants.MaxJwtSegmentCount + 1)
            {
                if (encodedJson[index] == '.')
                    dots.Add(index);

                index++;
            }

            EncodedToken = encodedJson;
            if (dots.Count == JwtConstants.JwsSegmentCount - 1)
            {
                IsSigned = !(dots[1] + 1 == encodedJson.Length);
                _hChars = encodedJson.ToCharArray(0, dots[0]);
                _pChars = encodedJson.ToCharArray(dots[0] + 1, dots[1] - dots[0] - 1);
                MessageBytes = Encoding.UTF8.GetBytes(encodedJson.ToCharArray(0, dots[1]));
                try
                {
                    _sChars = IsSigned ? encodedJson.ToCharArray(dots[1] + 1, encodedJson.Length - dots[1] - 1) : string.Empty.ToCharArray();
                    SignatureBytes = Base64UrlEncoder.UnsafeDecode(_sChars);
                    Header = new JsonClaimSet(Base64UrlEncoder.UnsafeDecode(_hChars));
                }
                catch(Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14102, encodedJson.Substring(0, dots[0]), encodedJson), ex));
                }

                try
                {
                    Payload = new JsonClaimSet(Base64UrlEncoder.UnsafeDecode(_pChars));
                }
                catch(Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14101, encodedJson.Substring(dots[0], dots[1] - dots[0]), encodedJson), ex));
                }
            }
            else if (dots.Count == JwtConstants.JweSegmentCount - 1)
            {
                _hChars = encodedJson.ToCharArray(0, dots[0]);
                if (_hChars.Length == 0)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14307, encodedJson)));

                HeaderAsciiBytes = Encoding.ASCII.GetBytes(_hChars);
                try
                {
                    Header = new JsonClaimSet(Base64UrlEncoder.UnsafeDecode(_hChars));
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14102, encodedJson.Substring(0, dots[0]), encodedJson), ex));
                }

                // dir does not have any key bytes
                char[] encryptedKeyBytes = encodedJson.ToCharArray(dots[0] + 1, dots[1] - dots[0] - 1);
                if (encryptedKeyBytes.Length != 0)
                    EncryptedKeyBytes = Base64UrlEncoder.UnsafeDecode(encryptedKeyBytes);

                char[] ivChars = encodedJson.ToCharArray(dots[1] + 1, dots[2] - dots[1] - 1);
                if (ivChars.Length == 0)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14308, encodedJson)));

                try
                {
                    InitializationVectorBytes = Base64UrlEncoder.UnsafeDecode(ivChars);
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14309, encodedJson, encodedJson), ex));
                }

                char[] authTagChars = encodedJson.ToCharArray(dots[3] + 1, encodedJson.Length - dots[3] - 1);
                if (authTagChars.Length == 0)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14310, encodedJson)));

                try
                {
                    AuthenticationTagBytes = Base64UrlEncoder.UnsafeDecode(authTagChars);
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14311, encodedJson, encodedJson), ex));
                }

                char[] cipherTextBytes = encodedJson.ToCharArray(dots[2] + 1, dots[3] - dots[2] - 1);
                if (cipherTextBytes.Length == 0)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14306, encodedJson)));

                try
                {
                    CipherTextBytes = Base64UrlEncoder.UnsafeDecode(encodedJson.ToCharArray(dots[2] + 1, dots[3] - dots[2] - 1));
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14312, encodedJson, encodedJson), ex));
                }
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14100, encodedJson)));
            }
        }

        /// <summary>
        ///
        /// </summary>
        internal byte[] SignatureBytes { get; set; }

        #region Claims
        /// <summary>
        /// Gets the 'value' of the 'actort' claim the payload.
        /// </summary>
        /// <remarks>
        /// If the 'actort' claim is not found, an empty string is returned.
        /// </remarks>
        public string Actor => _act.Value;

        /// <summary>
        /// Gets the 'value' of the 'alg' claim from the header.
        /// </summary>
        /// <remarks>
        /// Identifies the cryptographic algorithm used to encrypt or determine the value of the Content Encryption Key.
        /// Applicable to an encrypted JWT {JWE}.
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.1
        /// <para>
        /// If the 'alg' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Alg => _alg.Value;

        /// <summary>
        /// Gets the list of 'aud' claims from the payload.
        /// </summary>
        /// <remarks>
        /// Identifies the recipients that the JWT is intended for.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
        /// <para>
        /// If the 'aud' claim is not found, enumeration will be empty.
        /// </para>
        /// </remarks>
        public IEnumerable<string> Audiences => _audiences.Value;

        /// <summary>
        /// Gets a <see cref="IEnumerable{Claim}"/> where each claim in the JWT { name, value } is returned as a <see cref="Claim"/>.
        /// </summary>
        /// <remarks>
        /// A <see cref="Claim"/> requires each value to be represented as a string. If the value was not a string, then <see cref="Claim.Type"/> contains the json type.
        /// <see cref="JsonClaimValueTypes"/> and <see cref="ClaimValueTypes"/> to determine the json type.
        /// </remarks>
        public virtual IEnumerable<Claim> Claims
        {
            get
            {
                if (InnerToken != null)
                    return InnerToken.Claims;

                return Payload.Claims(Issuer ?? ClaimsIdentity.DefaultIssuer);

            }
        }

        #if !NET45
        /// <summary>
        /// 
        /// </summary>
        public virtual IDictionary<string, object> ClaimsIdentityProperties => Payload.ClaimsIdentityProperties;
        #endif

        /// <summary>
        /// Gets the 'value' of the 'cty' claim from the header.
        /// </summary>
        /// <remarks>
        /// Used by JWS applications to declare the media type[IANA.MediaTypes] of the secured content (the payload).
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.12 (JWE)
        /// see: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10 (JWS)
        /// <para>
        /// If the 'cty' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Cty => _cty.Value;

        /// <summary>
        /// Gets the 'value' of the 'enc' claim from the header.
        /// </summary>
        /// <remarks>
        /// Identifies the content encryption algorithm used to perform authenticated encryption
        /// on the plaintext to produce the ciphertext and the Authentication Tag.
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2
        /// </remarks>
        public string Enc => _enc.Value;

        /// <summary>
        /// Gets a <see cref="Claim"/> representing the { key, 'value' } pair corresponding to the provided <paramref name="key"/>.
        /// </summary>
        /// <remarks>
        /// A <see cref="Claim"/> requires each value to be represented as a string. If the value was not a string, then <see cref="Claim.Type"/> contains the json type.
        /// <see cref="JsonClaimValueTypes"/> and <see cref="ClaimValueTypes"/> to determine the json type.
        /// <para>
        /// If the key has no corresponding value, this method will throw.
        /// </para>
        /// </remarks>
        public Claim GetClaim(string key)
        {
            return Payload.GetClaim(key, Issuer ?? ClaimsIdentity.DefaultIssuer);
        }

        /// <summary>
        /// Gets the 'value' corresponding to key from the JWT header transformed as type 'T'.
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type are expected in a JWT token.
        /// The 5 basic types: number, string, true / false, nil, array (of basic types).
        /// This is not a general purpose translation layer for complex types.
        /// </remarks>
        /// <returns>The value as <typeparamref name="T"/>.</returns>
        /// <exception cref="ArgumentException">if claim is not found or a transformation to <typeparamref name="T"/> cannot be made.</exception>
        public T GetHeaderValue<T>(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw LogHelper.LogArgumentNullException(nameof(key));

            return Header.GetValue<T>(key);
        }

        /// <summary>
        /// Gets the 'value' corresponding to key from the JWT payload transformed as type 'T'.
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type are expected in a JWT token.
        /// The 5 basic types: number, string, true / false, nil, array (of basic types).
        /// This is not a general purpose translation layer for complex types.
        /// </remarks>
        /// <returns>The value as <typeparamref name="T"/>.</returns>
        /// <exception cref="ArgumentException">if claim is not found or a transformation to <typeparamref name="T"/> cannot be made.</exception>
        public T GetPayloadValue<T>(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (typeof(T).Equals(typeof(Claim)))
                return (T)(object)GetClaim(key);

            return Payload.GetValue<T>(key);
        }

        /// <summary>
        /// Gets the 'value' of the 'jti' claim from the payload.
        /// </summary>
        /// <remarks>
        /// Provides a unique identifier for the JWT.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
        /// <para>
        /// If the 'jti' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public override string Id => _id.Value;

        /// <summary>
        /// Gets the 'value' of the 'iat' claim converted to a <see cref="DateTime"/> from the payload.
        /// </summary>
        /// <remarks>
        /// Identifies the time at which the JWT was issued.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
        /// <para>
        /// If the 'iat' claim is not found, then <see cref="DateTime.MinValue"/> is returned.
        /// </para>
        /// </remarks>
        public DateTime IssuedAt => _iat.Value;

        /// <summary>
        /// Gets the 'value' of the 'iss' claim from the payload.
        /// </summary>
        /// <remarks>
        /// Identifies the principal that issued the JWT.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
        /// <para>
        /// If the 'iss' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public override string Issuer => _iss.Value;

        /// <summary>
        /// Gets the 'value' of the 'kid' claim from the header.
        /// </summary>
        /// <remarks>
        /// 'kid'is a hint indicating which key was used to secure the JWS.
        /// see: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4 (JWS)
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.6 (JWE)
        /// <para>
        /// If the 'kid' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Kid => _kid.Value;

        /// <summary>
        /// Gets the 'value' of the 'sub' claim from the payload.
        /// </summary>
        /// <remarks>
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
        /// Identifies the principal that is the subject of the JWT.
        /// <para>
        /// If the 'sub' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Subject => _sub.Value;

        /// <summary>
        /// Try to get a <see cref="Claim"/> representing the { key, 'value' } pair corresponding to the provided <paramref name="key"/>.
        /// </summary>
        /// <remarks>
        /// A <see cref="Claim"/> requires each value to be represented as a string. If the value was not a string, then <see cref="Claim.Type"/> contains the json type.
        /// <see cref="JsonClaimValueTypes"/> and <see cref="ClaimValueTypes"/> to determine the json type.
        /// </remarks>
        /// <returns>true if successful, false otherwise.</returns>
        public bool TryGetClaim(string key, out Claim value)
        {
            return Payload.TryGetClaim(key, Issuer ?? ClaimsIdentity.DefaultIssuer, out value);
        }

        /// <summary>
        /// Tries to get the value
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type expected in a JWT token.
        /// </remarks>
        /// <returns>true if successful, false otherwise.</returns>
        public bool TryGetValue<T>(string key, out T value)
        {
            if (string.IsNullOrEmpty(key))
            {
                value = default;
                return false;
            }

            return Payload.TryGetValue(key, out value);
        }

        /// <summary>
        /// Tries to get the value corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type expected in a JWT token.
        /// The 5 basic types: number, string, true / false, nil, array (of basic types).
        /// This is not a general purpose translation layer for complex types.
        /// </remarks>
        /// <returns>true if successful, false otherwise.</returns>
        public bool TryGetHeaderValue<T>(string key, out T value)
        {
            if (string.IsNullOrEmpty(key))
            {
                value = default;
                return false;
            }

            return Header.TryGetValue(key, out value);
        }

        /// <summary>
        /// Try to get the 'value' corresponding to key from the JWT payload transformed as type 'T'.
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type are expected in a JWT token.
        /// The 5 basic types: number, string, true / false, nil, array (of basic types).
        /// This is not a general purpose translation layer for complex types.
        /// </remarks>
        /// <returns>true if successful, false otherwise.</returns>
        public bool TryGetPayloadValue<T>(string key, out T value)
        {
            if (string.IsNullOrEmpty(key))
            {
                value = default;
                return false;
            }

            if (typeof(T).Equals(typeof(Claim)))
            {
                bool foundClaim = TryGetClaim(key, out var claim);
                value = (T)(object)claim;
                return foundClaim;
            }

            return Payload.TryGetValue(key, out value);
        }

        /// <summary>
        /// Gets the 'value' of the 'typ' claim from the header.
        /// </summary>
        /// <remarks>
        /// Is used by JWT applications to declare the media type.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
        /// <para>
        /// If the 'typ' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Typ => _typ.Value;

        /// <summary>
        /// Gets the 'value' of the 'x5t' claim from the header.
        /// </summary>
        /// <remarks>
        /// Is the base64url-encoded SHA-1 thumbprint(a.k.a.digest) of the DER encoding of the X.509 certificate used to sign this token.
        /// see : https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7
        /// <para>
        /// If the 'x5t' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string X5t => _x5t.Value;

        /// <summary>
        /// Gets the 'value' of the 'nbf' claim converted to a <see cref="DateTime"/> from the payload.
        /// </summary>
        /// <remarks>
        /// Identifies the time before which the JWT MUST NOT be accepted for processing.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
        /// <para>
        /// If the 'nbf' claim is not found, then <see cref="DateTime.MinValue"/> is returned.
        /// </para>
        /// </remarks>
        public override DateTime ValidFrom => _validFrom.Value;

        /// <summary>
        /// Gets the 'value' of the 'exp' claim converted to a <see cref="DateTime"/> from the payload.
        /// </summary>
        /// <remarks>
        /// Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
        /// <para>
        /// If the 'exp' claim is not found, then <see cref="DateTime.MinValue"/> is returned.
        /// </para>
        /// </remarks>
        public override DateTime ValidTo => _validTo.Value;

        /// <summary>
        /// Gets the 'value' of the 'zip' claim from the header.
        /// </summary>
        /// <remarks>
        /// The "zip" (compression algorithm) applied to the plaintext before encryption, if any.
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.3
        /// <para>
        /// If the 'zip' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Zip => _zip.Value;
        #endregion

        #region Factories for Lazy
        private string ActorFactory()
        {
            return (InnerToken == null) ? Payload.GetStringValue(JwtRegisteredClaimNames.Actort) : InnerToken.Payload.GetStringValue(JwtRegisteredClaimNames.Actort);
        }

        private string AlgFactory()
        {
            return Header.GetStringValue(JwtHeaderParameterNames.Alg);
        }

        private IEnumerable<string> AudiencesFactory()
        {
#if NET45
            if (Payload.TryGetValue(JwtRegisteredClaimNames.Aud, out JToken value))
            {
                if (value.Type is JTokenType.String)
                    return new List<string> { value.ToObject<string>() };
                else if (value.Type is JTokenType.Array)
                    return value.ToObject<List<string>>();
            }
#else
            if (Payload.TryGetValue(JwtRegisteredClaimNames.Aud, out JsonElement audiences))
            {
                if (audiences.ValueKind == JsonValueKind.String)
                    return new List<string> { audiences.GetString() };

                if (audiences.ValueKind == JsonValueKind.Array)
                {
                    List<string> retVal = new List<string>();
                    foreach (JsonElement jsonElement in audiences.EnumerateArray())
                        retVal.Add(jsonElement.ToString());

                    return retVal;
                }
            }
#endif
            return Enumerable.Empty<string>();
        }

        private string CtyFactory()
        {
            return Header.GetStringValue(JwtHeaderParameterNames.Cty);
        }

        private string EncFactory()
        {
            return Header.GetStringValue(JwtHeaderParameterNames.Enc);
        }

        private string EncodedHeaderFactory()
        {
            return new string(_hChars);
        }

        private string EncodedPayloadFactory()
        {
            return new string(_pChars);
        }

        private string EncodedSignatureFactory()
        {
            return new string(_sChars);
        }

        private string IdFactory()
        {
            return Payload.GetStringValue(JwtRegisteredClaimNames.Jti);
        }

        private DateTime IatFactory()
        {
            return Payload.GetDateTime(JwtRegisteredClaimNames.Iat);
        }

        private string IssuerFactory()
        {
            return Payload.GetStringValue(JwtRegisteredClaimNames.Iss);
        }

        private string KidFactory()
        {
            return Header.GetStringValue(JwtHeaderParameterNames.Kid);
        }

        private string SubFactory()
        {
            return Payload.GetStringValue(JwtRegisteredClaimNames.Sub);
        }

        private string TypFactory()
        {
            return Header.GetStringValue(JwtHeaderParameterNames.Typ);
        }

        private string X5tFactory()
        {
            return Header.GetStringValue(JwtHeaderParameterNames.X5t);
        }

        private DateTime ValidFromFactory()
        {
            return Payload.GetDateTime(JwtRegisteredClaimNames.Nbf);
        }

        private DateTime ValidToFactory()
        {
            return Payload.GetDateTime(JwtRegisteredClaimNames.Exp);
        }

        private string ZipFactory()
        {
            return Header.GetStringValue(JwtHeaderParameterNames.Zip);
        }
        #endregion
    }
}
