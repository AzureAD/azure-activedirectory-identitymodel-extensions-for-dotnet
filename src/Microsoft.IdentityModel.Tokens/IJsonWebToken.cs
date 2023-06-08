// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Interface that represents a JSON Web Token.
    /// </summary>
    public interface IJsonWebToken
    {
        /// <summary>
        /// Gets the 'alg' header parameter or an empty string if not found.
        /// </summary>
        /// <remarks>
        /// Identifies the cryptographic algorithm used to encrypt or determine the value of the Content Encryption Key.
        /// Applicable to an encrypted JWT {JWE}.
        /// <para>
        /// See: https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1
        /// </para>
        /// </remarks>
        public string Alg { get; }

        /// <summary>
        /// Gets the collection of 'aud' claims from the payload.
        /// The collection will be empty if no 'aud' claims are found.
        /// </summary>
        /// <remarks>
        /// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
        /// </remarks>
        public IEnumerable<string> Audiences { get; }

        /// <summary>
        /// Gets the value of the 'cty' header parameter or an empty string if not found.
        /// </summary>
        /// <remarks>
        /// Used by JWS applications to declare the media type[IANA.MediaTypes] of the secured content (the payload).
        /// <para>
        /// See: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.12 (JWE)
        /// </para>
        /// See: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10 (JWS)
        /// </remarks>
        public string Cty { get; }

        /// <summary>
        /// Gets the value of the 'enc' header parameter or an empty string if not found.
        /// </summary>
        /// <remarks>
        /// Identifies the content encryption algorithm used to perform authenticated encryption
        /// on the plaintext to produce the ciphertext and the Authentication Tag.
        /// See: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2
        /// </remarks>
        public string Enc { get; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// The original Base64UrlEncoded of the JWT.
        /// </remarks>
        public string EncodedToken { get; }

        /// <summary>
        /// Gets the value of the 'jti' claim from the payload or an empty string if not found.
        /// </summary>
        /// <remarks>
        /// Provides a unique identifier for the JWT.
        /// <para>
        /// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
        /// </para>
        /// </remarks>
        public string Id { get; }

        /// <summary>
        /// Gets the value of the 'iat' claim converted to a <see cref="DateTime"/> from the payload
        /// or <see cref="DateTime.MinValue"/> if not found.
        /// </summary>
        /// <remarks>
        /// Identifies the time at which the JWT was issued.
        /// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
        /// </remarks>
        public DateTime IssuedAt { get; }

        /// <summary>
        /// Gets the 'value' of the 'iss' claim from the payload or an empty string if not found.
        /// </summary>
        /// <remarks>
        /// Identifies the principal that issued the JWT.
        /// <para>
        /// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
        /// </para>
        /// </remarks>
        public string Issuer { get; }

        /// <summary>
        /// Gets the <see cref="IJsonWebToken"/> associated with this instance.
        /// </summary>
        /// <remarks>
        /// <para>
        /// See: https://datatracker.ietf.org/doc/html/rfc7516#section-2
        /// </para>
        /// For encrypted tokens {JWE}, this represents the JWT that was encrypted.
        /// <para>
        /// If the JWT is not encrypted, this value will be null.
        /// </para>
        /// </remarks>
        public IJsonWebToken InnerToken { get; }

        /// <summary>
        /// Gets the value of the 'kid' parameter from the header or an empty string if not found.
        /// </summary>
        /// <remarks>
        /// 'kid' is a hint indicating which key was used to secure the JWS.
        /// <para>
        /// see: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4 (JWS)
        /// </para>
        /// <para>
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.6 (JWE)
        /// </para>
        /// </remarks>
        public string Kid { get; }

        /// <summary>
        /// Gets the value of the 'sub' claim from the payload or an empty string if not found.
        /// </summary>
        /// <remarks>
        /// Identifies the principal that is the subject of the JWT.
        /// <para>
        /// See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
        /// </para>
        /// </remarks>
        string Subject { get; }

        /// <summary>
        /// Tries to get the value corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type expected in a JWT token.
        /// The 5 basic types: number, string, true / false, nil, array (of basic types).
        /// This is not a general purpose translation layer for complex types.
        /// </remarks>
        /// <returns><c>true</c> if successful, <c>false</c> otherwise.</returns>
        public bool TryGetHeaderValue<T>(string claimId, out T value);

        /// <summary>
        /// Try to get the 'value' corresponding to key from the JWT payload transformed as type <typeparamref name="T"/>.
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type are expected in a JWT token.
        /// The 5 basic types: number, string, true / false, nil, array (of basic types).
        /// This is not a general purpose translation layer for complex types.
        /// </remarks>
        /// <returns><c>true</c> if successful, <c>false</c> otherwise.</returns>
        public bool TryGetPayloadValue<T>(string claimId, out T value);

        /// <summary>
        /// Gets the value of the 'typ' parameter from the header or an empty string if not found.
        /// </summary>
        /// <remarks>
        /// Is used by JWT applications to declare the media type.
        /// <para>
        /// See: https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
        /// </para>
        /// </remarks>
        public string Typ { get; }

        /// <summary>
        /// Gets the value of the 'nbf' claim converted to a <see cref="DateTime"/> from the payload
        /// or <see cref="DateTime.MinValue"/> if not found.
        /// </summary>
        /// <remarks>
        /// Identifies the time before which the JWT MUST NOT be accepted for processing.
        /// <para>
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
        /// </para>
        /// </remarks>
        public DateTime ValidFrom { get; }

        /// <summary>
        /// Gets the value of the 'exp' claim converted to a <see cref="DateTime"/> from the payload
        /// or <see cref="DateTime.MinValue"/> if not found.
        /// </summary>
        /// <remarks>
        /// Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
        /// <para>
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
        /// </para>
        /// </remarks>
        public DateTime ValidTo { get; }

        /// <summary>
        /// Gets the value of the 'x5t' parameter from the header or an empty string if returned.
        /// </summary>
        /// <remarks>
        /// Is the base64url-encoded SHA-1 thumbprint(a.k.a.digest) of the DER encoding of the X.509 certificate used to sign this token.
        /// <para>
        /// See : https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7
        /// </para>
        /// </remarks>
        public string X5t { get; }

        /// <summary>
        /// Gets the value of the 'zip' parameter from the header or an empty string if not found.
        /// </summary>
        /// <remarks>
        /// The "zip" (compression algorithm) applied to the plaintext before encryption, if any.
        /// <para>
        /// See: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.3
        /// </para>
        /// </remarks>
        public string Zip { get; }
    }
}
