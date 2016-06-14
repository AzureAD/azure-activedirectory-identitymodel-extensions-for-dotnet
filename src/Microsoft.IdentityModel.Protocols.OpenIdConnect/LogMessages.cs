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

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
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
        internal const string IDX10105 = "IDX10105: NonceLifetime must be greater than zero. value: '{0}'";
        internal const string IDX10106 = "IDX10106: Error in deserializing to json: '{0}'";

        // protocol validation
        internal const string IDX10300 = "IDX10300: The hash claim: '{0}' in the id_token did not validate with against: '{1}', algorithm: '{2}'.";
        internal const string IDX10301 = "IDX10301: The algorithm: '{0}' specified in the jwt header could not be used to create a '{1}'. See inner exception for details.";
        internal const string IDX10302 = "IDX10302: The algorithm: '{0}' specified in the jwt header is not supported.";
        internal const string IDX10303 = "IDX10303: Validating hash of OIDC protocol message. Expected: '{0}'.";
        internal const string IDX10304 = "IDX10304: Validating 'c_hash' using id_token and code.";
        internal const string IDX10305 = "IDX10305: OpenIdConnectProtocolValidationContext.ProtocolMessage.Code is null, there is no 'code' in the OpenIdConnect Response to validate.";
        internal const string IDX10306 = "IDX10306: The 'c_hash' claim was not a string in the 'id_token', but a 'code' was in the OpenIdConnectMessage, 'id_token': '{0}'.";
        internal const string IDX10307 = "IDX10307: The 'c_hash' claim was not found in the id_token, but a 'code' was in the OpenIdConnectMessage, id_token: '{0}'";
        internal const string IDX10308 = "IDX10308: 'Azp' claim exists in the 'id_token' but 'ciient_id' is null. Cannot validate the 'azp' claim.";
        internal const string IDX10309 = "IDX10309: Validating 'at_hash' using id_token and access_token.";
        internal const string IDX10310 = "IDX10310: OpenIdConnectProtocolValidationContext.ProtocolMessage.AccessToken is null, there is no 'token' in the OpenIdConnect Response to validate.";
        internal const string IDX10311 = "IDX10311: The 'at_hash' claim was not a string in the 'id_token', but an 'access_token' was in the OpenIdConnectMessage, 'id_token': '{0}'.";
        internal const string IDX10312 = "IDX10312: The 'at_hash' claim was not found in the 'id_token', but a 'access_token' was in the OpenIdConnectMessage, 'id_token': '{0}'.";
        internal const string IDX10313 = "IDX10313: The id_token: '{0}' is not valid. Delegate threw exception, see inner exception for more details.";
        internal const string IDX10314 = "IDX10314: OpenIdConnectProtocol requires the jwt token to have an '{0}' claim. The jwt did not contain an '{0}' claim, jwt: '{1}'.";
        internal const string IDX10315 = "IDX10315: RequireAcr is 'true' (default is 'false') but jwt.PayLoad.Acr is 'null or whitespace', jwt: '{0}'.";
        internal const string IDX10316 = "IDX10316: RequireAmr is 'true' (default is 'false') but jwt.PayLoad.Amr is 'null or whitespace', jwt: '{0}'.";
        internal const string IDX10317 = "IDX10317: RequireAuthTime is 'true' (default is 'false') but jwt.PayLoad.AuthTime is 'null or whitespace', jwt: '{0}'.";
        internal const string IDX10318 = "IDX10318: RequireAzp is 'true' (default is 'false') but jwt.PayLoad.Azp is 'null or whitespace', jwt: '{0}'.";
        internal const string IDX10319 = "IDX10319: Validating the nonce claim found in the id_token.";
        internal const string IDX10320 = "IDX10320: RequireNonce is '{0}' but OpenIdConnectProtocolValidationContext.Nonce is null. A nonce cannot be validated. If you don't need to check the nonce, set OpenIdConnectProtocolValidator.RequireNonce to 'false'.";
        internal const string IDX10321 = "IDX10321: The 'nonce' found in the jwt token did not match the expected nonce.\nexpected: '{0}'\nfound in jwt: '{1}'.\njwt: '{2}'.";
        internal const string IDX10322 = "IDX10322: RequireNonce is false, validationContext.Nonce is null and there is no 'nonce' in the OpenIdConnect Response to validate.";
        internal const string IDX10323 = "IDX10323: RequireNonce is '{0}', the OpenIdConnect request contained nonce but the jwt does not contain a 'nonce' claim. The nonce cannot be validated. If you don't need to check the nonce, set OpenIdConnectProtocolValidator.RequireNonce to 'false'.\n jwt: '{1}'.";
        internal const string IDX10324 = "IDX10324: The 'nonce' has expired: '{0}'. Time from 'nonce': '{1}', Current Time: '{2}'. NonceLifetime is: '{3}'.";
        internal const string IDX10325 = "IDX10325: The 'nonce' did not contain a timestamp: '{0}'.\nFormat expected is: <epochtime>.<noncedata>.";
        internal const string IDX10326 = "IDX10326: The 'nonce' timestamp could not be converted to a positive integer (greater than 0).\ntimestamp: '{0}'\nnonce: '{1}'.";
        internal const string IDX10327 = "IDX10327: The 'nonce' timestamp: '{0}', could not be converted to a DateTime using DateTime.FromBinary({0}).\nThe value must be between: '{1}' and '{2}'.";
        internal const string IDX10328 = "IDX10328: Generating nonce for openIdConnect message.";
        internal const string IDX10329 = "IDX10329: RequireState is '{0}' but the OpenIdConnectProtocolValidationContext.State is null. State cannot be validated.";
        internal const string IDX10330 = "IDX10330: RequireState is '{0}', the OpenIdConnect Request contained 'state', but the Response does not contain 'state'.";
        internal const string IDX10331 = "IDX10331: The 'state' parameter in the message: '{0}', does not equal the 'state' in the context: '{1}'.";
        internal const string IDX10332 = "IDX10332: OpenIdConnectProtocolValidationContext.ValidatedIdToken is null. There is no 'id_token' to validate against.";
        internal const string IDX10333 = "IDX10333: OpenIdConnectProtocolValidationContext.ProtocolMessage is null, there is no OpenIdConnect Response to validate.";
        internal const string IDX10334 = "IDX10334: Both 'id_token' and 'code' are null in OpenIdConnectProtocolValidationContext.ProtocolMessage received from Authorization Endpoint. Cannot process the message.";
        internal const string IDX10335 = "IDX10335: 'refresh_token' cannot be present in a response message received from Authorization Endpoint.";
        internal const string IDX10336 = "IDX10336: Both 'id_token' and 'access_token' should be present in OpenIdConnectProtocolValidationContext.ProtocolMessage received from Token Endpoint. Cannot process the message.";
        internal const string IDX10337 = "IDX10337: OpenIdConnectProtocolValidationContext.UserInfoEndpointResponse is null or empty, there is no OpenIdConnect Response to validate.";
        internal const string IDX10338 = "IDX10338: Subject claim present in 'id_token': '{0}' does not match the claim received from UserInfo Endpoint: '{1}'.";
        internal const string IDX10339 = "IDX10339: The 'id_token' contains multiple audiences but 'azp' claim is missing.";
        internal const string IDX10340 = "IDX10340: The 'id_token' contains 'azp' claim but its value is not equal to Client Id. 'azp': '{0}'. clientId: '{1}'.";
        internal const string IDX10341 = "IDX10341: 'RequireState' = false, OpenIdConnectProtocolValidationContext.State is null and there is no 'state' in the OpenIdConnect response to validate.";
        internal const string IDX10342 = "IDX10342: 'RequireStateValidation' = false, not validating the state.";
        internal const string IDX10343 = "IDX10343: Unable to parse response from UserInfo endpoint: '{0}'";
        internal const string IDX10344 = "IDX10344: OpenIdConnectProtocolValidationContext.ProtocolMessage.IdToken is null, no id_token present to validate userinfo response against.";
        internal const string IDX10345 = "IDX10345: OpenIdConnectProtocolValidationContext.UserInfoEndpointResponse does not contain a 'sub' claim, cannot validate.";
        internal const string IDX10346 = "IDX10346: OpenIdConnectProtocolValidationContext.ValidatedIdToken does not contain a 'sub' claim, cannot validate.";
        internal const string IDX10347 = "IDX10347: Validating the 'c_hash' failed, see inner exception.";
        internal const string IDX10348 = "IDX10348: Validating the 'at_hash' failed, see inner exception.";

        // configuration retrieval errors
        internal const string IDX10800 = "IDX10800: JsonWebKeySet must have a 'Keys' element.";
        internal const string IDX10801 = "IDX10801: Unable to create an RSA public key from the Exponent and Modulus found in the JsonWebKey: E: '{0}', N: '{1}'. See inner exception for additional details.";
        internal const string IDX10802 = "IDX10802: Unable to create an X509Certificate2 from the X509Data: '{0}'. See inner exception for additional details.";
        internal const string IDX10803 = "IDX10803: Unable to obtain configuration from: '{0}'. Inner Exception: '{1}'.";
        internal const string IDX10804 = "IDX10804: Unable to retrieve document from: '{0}'.";
        internal const string IDX10805 = "IDX10805: Obtaining information from metadata endpoint: '{0}'";
        internal const string IDX10806 = "IDX10806: Deserializing json string into json web keys.";
        internal const string IDX10807 = "IDX10807: Adding signing keys into the configuration object.";
        internal const string IDX10808 = "IDX10808: Deserializing json into OpenIdConnectConfiguration object: '{0}'.";
        internal const string IDX10809 = "IDX10809: Serializing OpenIdConfiguration object to json string.";
        internal const string IDX10810 = "IDX10810: Initializing an instance of OpenIdConnectConfiguration from a dictionary.";
        internal const string IDX10811 = "IDX10811: Deserializing the string: '{0}' obtained from metadata endpoint into openIdConnectConfiguration object.";
        internal const string IDX10812 = "IDX10812: Retrieving json web keys from: '{0}'.";
        internal const string IDX10813 = "IDX10813: Deserializing json web keys: '{0}'.";
        internal const string IDX10814 = "IDX10814: Cannot read file from the address: '{0}'. File does not exist.";
        internal const string IDX10815 = "IDX10815: Error deserializing json: '{0}' into '{1}'.";

#pragma warning restore 1591


    }
}
