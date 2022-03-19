# JsonClaimSets

# Issue
The original model for processing claims from tokens in the .NET ClaimsIdentity requires all objects to be mapped to strings. This is inefficient for users that want to work with json objects which is natural for users of JsonWebTokens (JWT). While constructing the ClaimsIdentity, the 'json' type is remembered, a conversion to json is required for those json users. This is a performance issue.
When the ClaimsIdentity was designed it was assumed a small number of claims would be in a token so a linear search was implemeted. In today's world it is common for a token to contain a large number of claims and the linear seach has been identified as performance issue.
When the JWT is parsed and validated many string -> bytes -> string operations are performed, this has also been identified as a performance issue. Parsing a JWT will perform one transformation to bytes and use System.Text.Json objects to perform all operations against bytes.

# Proposal
- Provide properties for standard claims such as:
-- Audience
-- Expiration
-- Scopes
-- Tid
-- ...
- Develop a new class JsonClaimSet to hold all claims that is accessable in constant time and returns System.Text.Json objects.
- Provide access for claims in constant time from the JWT payload and header 
-- conversions will be provided
-- templated types

# Types

## JsonWebToken
```cs
   public JsonWebToken(string jwtEncodedString)
        {
        }

        public JsonWebToken(string header, string payload)
        {
        }

        public string Actor { get; }

        /// <summary>
        /// Gets the 'value' of the 'alg' claim { alg, 'value' }.
        /// </summary>
        /// <remarks>If the 'alg' claim is not found, an empty string is returned.</remarks>   
        public string Alg { get; }
		
        /// <summary>
        /// Gets the list of 'aud' claim { aud, 'value' }.
        /// </summary>
        /// <remarks>If the 'aud' claim is not found, enumeration will be empty.</remarks>
        public IEnumerable<string> Audiences { get; }

        /// <summary>
        /// Gets the AuthenticationTag from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string AuthenticationTag { get; }

        /// <summary>
        /// Gets the Ciphertext from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string Ciphertext { get; }

        /// <summary>
        /// Gets the 'value' of the 'cty' claim { cty, 'value' }.
        /// </summary>
        /// <remarks>If the 'cty' claim is not found, an empty string is returned.</remarks>   
        public string Cty => { get; }

        /// <summary>
        /// Gets the 'value' of the 'enc' claim { enc, 'value' }.
        /// </summary>
        /// <remarks>If the 'enc' value is not found, an empty string is returned.</remarks>   
        public string Enc => { get; }

        /// <summary>
        /// Gets the EncryptedKey from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string EncryptedKey { get; }

        /// <summary>
        /// Gets the EncodedPayload from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string EncodedPayload { get; }

        /// <summary>
        /// Gets the 'value' of the 'jti' claim { jti, ''value' }.
        /// </summary>
        /// <remarks>If the 'jti' claim is not found, an empty string is returned.</remarks>
        public override string Id => { get; }

        /// <summary>
        /// Gets the InitializationVector from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string InitializationVector { get; }

        /// <summary>
        /// Gets the <see cref="JsonWebToken"/> associated with this instance.
        /// </summary>
        public JsonWebToken InnerToken { get; }

        /// <summary>
        /// Gets the 'value' of the 'iat' claim { iat, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'iat' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime IssuedAt => { get; }

        /// <summary>
        /// Gets the 'value' of the 'iss' claim { iss, 'value' }.
        /// </summary>
        /// <remarks>If the 'iss' claim is not found, an empty string is returned.</remarks>   
        public override string Issuer => { get; }

        /// <summary>
        /// Gets the 'value' of the 'kid' claim { kid, 'value' }.
        /// </summary>
        /// <remarks>If the 'kid' claim is not found, an empty string is returned.</remarks>   
        public string Kid => { get; }

        /// <summary>
        /// Gets the EncodedHeader from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string EncodedHeader { get; }

        /// <summary>
        /// Gets the EncodedSignature from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>The original JSON Compact serialized format passed into the constructor. <see cref="JsonWebToken(string)"/></remarks>
        public string EncodedSignature { get; }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        public string EncodedToken { get; }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that was used to sign this token.
        /// </summary>
        public override SecurityKey SigningKey { get; }

        /// <summary>
        /// Gets the 'value' of the 'sub' claim { sub, 'value' }.
        /// </summary>
        /// <remarks>If the 'sub' claim is not found, an empty string is returned.</remarks>   
        public string Subject { get; }

        /// <summary>
        /// Gets the 'value' of the 'typ' claim { typ, 'value' }.
        /// </summary>
        /// <remarks>If the 'typ' claim is not found, an empty string is returned.</remarks>   
        public string Typ { get; }

        /// <summary>
        /// Gets the 'value' of the 'kid' claim { kid, 'value' }.
        /// </summary>
        /// <remarks>If the 'kid' claim is not found, an empty string is returned.</remarks>   
        public string X5t => _x5t.Value;

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
        /// Gets the 'value' of the 'zip' claim { zip, 'value' }.
        /// </summary>
        /// <remarks>If the 'zip' claim is not found, an empty string is returned.</remarks>   
        public string Zip => _zip.Value;

        /// <summary>
        /// Gets a <see cref="Claim"/> representing the { key, 'value' } pair corresponding to the provided <paramref name="key"/>.
        /// </summary>
        /// <remarks>If the key has no corresponding value, this method will throw.</remarks>   
        public Claim GetClaim(string key)
        {
        }

        /// <summary>
        /// Gets the 'value' corresponding to the provided key from the JWT payload { key, 'value' }.
        /// </summary>
        /// <remarks>If the key has no corresponding value, this method will throw. </remarks>   
        public T GetPayloadValue<T>(string key)
        {
        }

        /// <summary>
        /// Tries to get the <see cref="Claim"/> representing the { key, 'value' } pair corresponding to the provided <paramref name="key"/>.
        /// </summary>
        /// <remarks>If the key has no corresponding value, returns false. Otherwise returns true. </remarks>   
        public bool TryGetClaim(string key, out Claim value)
        {
        }

        /// <summary>
        /// Tries to get the 'value' corresponding to the provided key from the JWT payload { key, 'value' }.
        /// </summary>
        /// <remarks>If the key has no corresponding value, returns false. Otherwise returns true. </remarks>   
        public bool TryGetPayloadValue<T>(string key, out T value)
        {
        }

        /// <summary>
        /// Gets the 'value' corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        /// <remarks>If the key has no corresponding value, this method will throw. </remarks>   
        public T GetHeaderValue<T>(string key)
        {
        }

        /// <summary>
        /// Tries to get the value corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        /// <remarks>If the key has no corresponding value, returns false. Otherwise returns true. </remarks>   
        public bool TryGetHeaderValue<T>(string key, out T value)
        {
        }
    }

             
```
JsonClaimSet

