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

namespace System.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// Log messages and codes
    /// </summary>
    internal static class LogMessages
    {
        #pragma warning disable 1591
        // general
        internal const string IDX10000 = "IDX10000: The parameter '{0}' cannot be a 'null' or an empty object.";

        // properties, configuration 
        internal const string IDX10101 = "IDX10101: MaximumTokenSizeInBytes must be greater than zero. value: '{0}'";
        internal const string IDX10104 = "IDX10104: TokenLifetimeInMinutes must be greater than zero. value: '{0}'";

        // token validation
        internal const string IDX10209 = "IDX10209: token has length: '{0}' which is larger than the MaximumTokenSizeInBytes: '{1}'.";
        internal const string IDX10230 = "IDX10230: Lifetime validation failed. Delegate returned false, securitytoken: '{0}'.";
        internal const string IDX10231 = "IDX10231: Audience validation failed. Delegate returned false, securitytoken: '{0}'.";
        internal const string IDX10232 = "IDX10232: IssuerSigningKey validation failed. Delegate returned false, securityKey: '{0}'.";
        internal const string IDX10241 = "IDX10241: Security token validated. token: '{0}'.";
        internal const string IDX10242 = "IDX10242: Security token: '{0}' has a valid signature.";
        internal const string IDX10243 = "IDX10243: Reading issuer signing keys from validaiton parameters.";
        internal const string IDX10244 = "IDX10244: Issuer is null or empty. Using runtime default for creating claims '{0}'.";

        // SecurityTokenHandler messages
        internal const string IDX10401 = "IDX10401: Expires: '{0}' must be after NotBefore: '{1}'.";

        // SignatureValidation
        internal const string IDX10500 = "IDX10500: Signature validation failed. There are no security keys to use to validate the signature";
        internal const string IDX10501 = "IDX10501: Signature validation failed. Unable to match 'kid': '{0}', \ntoken: '{1}'.";
        internal const string IDX10503 = "IDX10503: Signature validation failed. Keys tried: '{0}'.\nExceptions caught:\n '{1}'.\ntoken: '{2}'";
        internal const string IDX10504 = "IDX10504: Unable to validate signature, token does not have a signature: '{0}'";
        internal const string IDX10505 = "IDX10505: Signature validation failed. The user defined 'Delegate' specified on TokenValidationParameters returned null when validating token: '{0}'.";
        internal const string IDX10506 = "IDX10506: Signature validation failed. The user defined 'Delegate' specified on TokenValidationParameters did not return a '{0}', but returned a '{1}' when validating token: '{2}'.";
        internal const string IDX10507 = "IDX10507: Signature validation failed. ValidateSignature returned null when validating token: '{0}'.";

        // Crypto Errors
        internal const string IDX10635 = "IDX10635: Unable to create signature. '{0}' returned a null '{1}'. SecurityKey: '{2}', Algorithm: '{3}'";
        internal const string IDX10636 = "IDX10636: CryptoProviderFactory.CreateForVerifying returned null for key: '{0}', signatureAlgorithm: '{1}'.";
        internal const string IDX10644 = "IDX10644: Creating raw signature using the signature provider.";
        internal const string IDX10645 = "IDX10645: Creating raw signature using the signature credentials.";
        internal const string IDX10646 = "IDX10646: CryptoProviderFactory.CreateForSigning returned null for key: '{0}', signatureAlgorithm: '{1}'.";

        // JWT specific errors
        internal const string IDX10700 = "IDX10700: Error found while parsing date time. The '{0}' claim has value '{1}' which is could not be parsed to an integer.";
        internal const string IDX10701 = "IDX10701: Error found while parsing date time. The '{0}' claim has value '{1}' does not lie in the valid range.";
        internal const string IDX10702 = "IDX10702: Jwt header type specified, must be '{0}' or '{1}'.  Type received: '{2}'.";
        internal const string IDX10703 = "IDX10703: Unable to decode the '{0}': '{1}' as Base64url encoded string. jwtEncodedString: '{2}'.";
        internal const string IDX10704 = "IDX10704: Cannot set inner IssuerTokenResolver to self.";
        internal const string IDX10705 = "IDX10705: The SigningKeyIdentifier was of type: '{0}' and was expected to be encoded as a Base64UrlEncoded string. See inner exception for more details.";
        internal const string IDX10706 = "IDX10706: '{0}' can only write SecurityTokens of type: '{1}', 'token' type is: '{2}'.";
        internal const string IDX10707 = "IDX10707: '{0}' cannot read this xml: '{1}'. The reader needs to be positioned at an element: '{2}', within the namespace: '{3}', with an attribute: '{4}' equal to one of the following: '{5}', '{6}'.";
        internal const string IDX10708 = "IDX10708: '{0}' cannot read this string: '{1}'.\nThe string needs to be in compact JSON format, which is of the form: '<Base64UrlEncodedHeader>.<Base64UrlEndcodedPayload>.<OPTIONAL, Base64UrlEncodedSignature>'.";
        internal const string IDX10709 = "IDX10709: '{0}' is not well formed: '{1}'. The string needs to be in compact JSON format, which is of the form: '<Base64UrlEncodedHeader>.<Base64UrlEndcodedPayload>.<OPTIONAL, Base64UrlEncodedSignature>'.";
        internal const string IDX10710 = "IDX10710: Only a single 'Actor' is supported. Found second claim of type: '{0}', value: '{1}'";
        internal const string IDX10711 = "IDX10711: actor.BootstrapContext is not a string AND actor.BootstrapContext is not a JWT";
        internal const string IDX10712 = "IDX10712: actor.BootstrapContext is null. Creating the token using actor.Claims.";
        internal const string IDX10713 = "IDX10713: Creating actor value using actor.BootstrapContext(as string)";
        internal const string IDX10714 = "IDX10714: Creating actor value using actor.BootstrapContext.rawData";
        internal const string IDX10715 = "IDX10715: Creating actor value by writing the JwtSecurityToken created from actor.BootstrapContext";
        internal const string IDX10716 = "IDX10716: Decoding token: '{0}' into header, payload and signature.";
        internal const string IDX10717 = "IDX10717: Deserializing header: '{0}' from the token.";
        internal const string IDX10718 = "IDX10718: Deserializing payload: '{0}' from the token.";
        internal const string IDX10719 = "IDX10719: Token string length greater than maximum length allowed. Token string length: {0}";
        internal const string IDX10720 = "IDX10720: Token string does not match the token format: header.payload.signature";
        internal const string IDX10721 = "IDX10721: Creating JwtSecurityToken: Issuer: '{0}', Audience: '{1}'";
        internal const string IDX10722 = "IDX10722: Creating security token from the header: '{0}', payload: '{1}' and raw signature: '{2}'.";

#pragma warning restore 1591


    }
}
