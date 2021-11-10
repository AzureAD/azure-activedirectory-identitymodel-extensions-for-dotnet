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
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

#if !NET45
using System.Text.Json;
#endif

namespace Microsoft.IdentityModel.JsonWebTokens
{

    /// <summary>
    /// A <see cref="SecurityToken"/> designed for representing a JSON Web Token (JWT).
    /// </summary>
    public class JsonWebToken : SecurityToken
    {
        internal bool HasSignature { get; set; }
//        private byte[] _messageBytes;

        private Lazy<string> _act;
        private Lazy<string> _alg;
        private Lazy<IEnumerable<string>> _audiences;
        private Lazy<string> _cty;
        private Lazy<string> _enc;
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
        //internal byte[] _initializationVectorBytes;
        //internal byte[] _authenticationTagBytes;
        //internal byte[] _encodedHeaderAsciiBytes;
        //internal byte[] _encryptedKeyBytes;

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
        /// Gets the 'value' of the 'actort' claim { actort, 'value' }.
        /// </summary>
        /// <remarks>If the 'actort' claim is not found, an empty string is returned.</remarks>
        // TODO - ensure string.Empty is not found.
        public string Actor => _act.Value;

        /// <summary>
        /// Gets a <see cref="IEnumerable{Claim}"/> where each claim in the JWT { name, value } is returned as a <see cref="Claim"/>.
        /// </summary>
        /// <remarks>
        /// A <see cref="Claim"/> requires each value to be represented as a string. If the value was not a string, then <see cref="Claim.Type"/> contains the json type.
        /// <see cref="JsonClaimValueTypes"/> and <see cref="ClaimValueTypes"/> to determine the json type.
        /// </remarks>
        public virtual IEnumerable<Claim> ActorClaims
        {
            // TODO - use actor Claims.
            get
            {
                if (InnerToken != null)
                    return InnerToken.Claims;

                return Payload.Claims(Issuer ?? ClaimsIdentity.DefaultIssuer);

            }
        }

        /// <summary>
        /// Gets the 'value' of the 'alg' claim { alg, 'value' }.
        /// </summary>
        /// <remarks>If the 'alg' claim is not found, an empty string is returned.</remarks>   
        public string Alg => _alg.Value;

        /// <summary>
        /// Gets the list of 'aud' claim { aud, 'value' }.
        /// </summary>
        /// <remarks>If the 'aud' claim is not found, enumeration will be empty.</remarks>
        public IEnumerable<string> Audiences => _audiences.Value;

        /// <summary>
        /// Gets the AuthenticationTag from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string AuthenticationTag
        {
            // TODO - use lazy singleton
            get
            {
                return AuthenticationTagBytes == null ? string.Empty : UTF8Encoding.UTF8.GetString(AuthenticationTagBytes);
            }
        }

        /// <summary>
        /// Gets the Ciphertext from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string Ciphertext
        {
            // TODO - use lazy singleton
            get
            {
                return CiphertextBytes == null ? string.Empty : UTF8Encoding.UTF8.GetString(CiphertextBytes);
            }
        }

        /// <summary>
        /// Gets a <see cref="IEnumerable{Claim}"/><see cref="Claim"/> for each JSON { name, value }.
        /// </summary>
        public virtual IEnumerable<Claim> Claims
        {
            get
            {
                if (InnerToken != null)
                    return InnerToken.Claims;

                return Payload.Claims(Issuer ?? ClaimsIdentity.DefaultIssuer);

            }
        }

        /// <summary>
        /// Gets the 'value' of the 'cty' claim { cty, 'value' }.
        /// </summary>
        /// <remarks>If the 'cty' claim is not found, an empty string is returned.</remarks>   
        public string Cty => _cty.Value;

        /// <summary>
        /// Gets the 'value' of the 'enc' claim { enc, 'value' }.
        /// </summary>
        /// <remarks>If the 'enc' value is not found, an empty string is returned.</remarks>   
        public string Enc => _enc.Value;

        /// <summary>
        /// Gets the EncryptedKey from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string EncryptedKey { get; internal set; }

        internal bool HasPayloadClaim(string claimName)
        {
            return Payload.HasClaim(claimName);
        }

        /// <summary>
        /// Represents the cryptographic operations applied to the JWT and optionally any additional properties of the JWT. 
        /// </summary>
        internal JsonClaimSet Header { get; private set; }

        /// <summary>
        /// Gets the 'value' of the 'jti' claim { jti, ''value' }.
        /// </summary>
        /// <remarks>If the 'jti' claim is not found, an empty string is returned.</remarks>
        public override string Id => _id.Value;

        /// <summary>
        /// Gets the InitializationVector from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string InitializationVector { get; private set; }

        /// <summary>
        /// Gets the <see cref="JsonWebToken"/> associated with this instance.
        /// </summary>
        public JsonWebToken InnerToken { get; internal set; }

        /// <summary>
        /// Gets the 'value' of the 'iat' claim { iat, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'iat' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime IssuedAt => _iat.Value;

        /// <summary>
        /// Gets the 'value' of the 'iss' claim { iss, 'value' }.
        /// </summary>
        /// <remarks>If the 'iss' claim is not found, an empty string is returned.</remarks>   
        public override string Issuer => _iss.Value;

        /// <summary>
        /// Gets the 'value' of the 'kid' claim { kid, 'value' }.
        /// </summary>
        /// <remarks>If the 'kid' claim is not found, an empty string is returned.</remarks>   
        public string Kid => _kid.Value;

        /// <summary>
        /// Represents the JSON payload.
        /// </summary>
        internal JsonClaimSet Payload { get; set; }

        /// <summary>
        /// Gets the EncodedHeader from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// The original Base64UrlEncoded string of the JWT header.
        /// </remarks>
        public string EncodedHeader { get; private set; }

        /// <summary>
        /// Gets the EncodedPayload from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// The original Base64UrlEncoded of the JWT payload.
        /// </remarks>
        public string EncodedPayload { get; private set; }

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

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override SecurityKey SecurityKey { get; }

        /// <summary>
        /// Not implemented.
        /// </summary>
        public override SecurityKey SigningKey
        {
            set;
            get;
        }

        /// <summary>
        /// Gets the 'value' of the 'sub' claim { sub, 'value' }.
        /// </summary>
        /// <remarks>If the 'sub' claim is not found, an empty string is returned.</remarks>   
        public string Subject => _sub.Value;

        /// <summary>
        /// Gets the 'value' of the 'typ' claim { typ, 'value' }.
        /// </summary>
        /// <remarks>If the 'typ' claim is not found, an empty string is returned.</remarks>   
        public string Typ => _typ.Value;

        /// <summary>
        /// Gets the 'value' of the 'nbf' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'nbf' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidFrom => _validFrom.Value;

        /// <summary>
        /// Gets the 'value' of the 'exp' claim { exp, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'exp' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidTo => _validTo.Value;

        /// <summary>
        /// Gets the 'value' of the 'x5t' claim { x5t, 'value' }.
        /// </summary>
        /// <remarks>If the 'x5t' claim is not found, an empty string is returned.</remarks>   
        public string X5t => _x5t.Value;

        /// <summary>
        /// Gets the 'value' of the 'zip' claim { zip, 'value' }.
        /// </summary>
        /// <remarks>If the 'zip' claim is not found, an empty string is returned.</remarks>   
        public string Zip => _zip.Value;

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
                value = default(T);
                return false;
            }

            if (typeof(T).Equals(typeof(Claim)))
            {
                var foundClaim = TryGetClaim(key, out var claim);
                value = (T)(object)claim;
                return foundClaim;
            }

            return Payload.TryGetValue<T>(key, out value);
        }

        /// <summary>
        /// Try to get the 'value' corresponding to key from the JWT header transformed as type 'T'.
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type are expected in a JWT token.
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

            return Header.TryGetValue<T>(key, out value);
        }

        #region New Json Work

        private void Initialize()
        {
            _act = new Lazy<string>(ActorFactory);
            _alg = new Lazy<string>(AlgFactory);
            _audiences = new Lazy<IEnumerable<string>>(AudiencesFactory);
            _cty = new Lazy<string>(CtyFactory);
            _enc = new Lazy<string>(EncFactory);
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

        internal byte[] AuthenticationTagBytes { get; private set; }

        internal byte[] CiphertextBytes { get; private set; }

        private string CtyFactory()
        {
            return Header.GetStringValue(JwtHeaderParameterNames.Cty);
        }

        internal byte[] EncodedHeaderAsciiBytes { get; private set; }

        private string EncFactory()
        {
            return Header.GetStringValue(JwtHeaderParameterNames.Enc);
        }

        private string EncodedSignatureFactory()
        {
            if (SignatureBytes == null)
                return new string((char[])null);

            return Base64UrlEncoder.Encode(SignatureBytes);
        }

        internal byte[] EncryptedKeyBytes { get; private set; }

        private string IdFactory()
        {
            return Payload.GetStringValue(JwtRegisteredClaimNames.Jti);
        }

        private DateTime IatFactory()
        {
            return Payload.GetDateTime(JwtRegisteredClaimNames.Iat);
        }

        internal byte[] InitializationVectorBytes { get; private set; }

        internal string IssuerFactory()
        {
            return Payload.GetStringValue(JwtRegisteredClaimNames.Iss);
        }

        private string KidFactory()
        {
            return Header.GetStringValue(JwtHeaderParameterNames.Kid);
        }

        /// <summary>
        ///
        /// </summary>
        internal byte[] SignatureBytes { get; private set;}

        /// <summary>
        ///
        /// </summary>
        internal byte[] MessageBytes { get; private set; }

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
                if (dots[1] + 1 == encodedJson.Length)
                {
                    HasSignature = false;
                    // TODO - have fixed value for this.
                    SignatureBytes = Base64UrlEncoder.DecodeBytes(string.Empty);
                }
                else
                {
                    HasSignature = true;
                    SignatureBytes = Base64UrlEncoder.DecodeBytes(encodedJson.Substring(dots[1] + 1, encodedJson.Length - dots[1] - 1));
                }

                //_hChars = encodedJson.ToCharArray(0, dots[0]);
                //_pChars = encodedJson.ToCharArray(dots[0] + 1, dots[1] - dots[0] - 1);
                MessageBytes = Encoding.UTF8.GetBytes(encodedJson.ToCharArray(0, dots[1]));
                EncodedHeader = encodedJson.Substring(0, dots[0]);
                try
                {
                    Header = new JsonClaimSet(Base64UrlEncoder.DecodeBytes(EncodedHeader));
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14102, encodedJson.Substring(0, dots[0]), encodedJson), ex));
                }

                EncodedPayload = encodedJson.Substring(dots[0] + 1, dots[1] - dots[0] - 1);
                try
                {
                    Payload = new JsonClaimSet(Base64UrlEncoder.DecodeBytes(EncodedPayload));
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14101, encodedJson.Substring(dots[0], dots[1] - dots[0]), encodedJson), ex));
                }
            }
            else if (dots.Count == JwtConstants.JweSegmentCount - 1)
            {
                string encodedHeader = encodedJson.Substring(0, dots[0]);
                EncodedHeaderAsciiBytes = Encoding.ASCII.GetBytes(encodedHeader);
                EncryptedKeyBytes = Base64UrlEncoder.DecodeBytes(encodedJson.Substring(dots[0] + 1, dots[1] - dots[0] - 1));
                InitializationVectorBytes = Base64UrlEncoder.DecodeBytes(encodedJson.Substring(dots[1] + 1, dots[2] - dots[1] - 1));
                CiphertextBytes = Base64UrlEncoder.DecodeBytes(encodedJson.Substring(dots[2] + 1, dots[3] - dots[2] - 1));
                if (CiphertextBytes.Length == 0)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX14306));

                AuthenticationTagBytes = Base64UrlEncoder.DecodeBytes(encodedJson.Substring(dots[3] + 1, encodedJson.Length - dots[3] - 1));
                try
                {
                    Header = new JsonClaimSet(Base64UrlEncoder.DecodeBytes(encodedHeader));
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14102, encodedJson.Substring(0, dots[0]), encodedJson), ex));
                }
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14100, encodedJson)));
            }

            NumberOfSegments = dots.Count + 1;
        }

        internal int NumberOfSegments { get; private set; }

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

        internal DateTime ValidFromFactory()
        {
            return Payload.GetDateTime(JwtRegisteredClaimNames.Nbf);
        }

        internal DateTime ValidToFactory()
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
