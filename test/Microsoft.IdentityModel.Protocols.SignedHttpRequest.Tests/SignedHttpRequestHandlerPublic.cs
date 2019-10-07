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
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.SignedHttpRequest;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    /// <summary>
    /// Mock SignedHttpRequestHandler.
    /// </summary>
    public class SignedHttpRequestHandlerPublic : SignedHttpRequestHandler
    {
        public string CreateHttpRequestHeaderPublic(SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            return base.CreateHttpRequestHeader(signedHttpRequestDescriptor);
        }

        public string CreateHttpRequestPayloadPublic(SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            return base.CreateHttpRequestPayload(signedHttpRequestDescriptor);
        }

        public async Task<string> SignHttpRequestPublicAsync(string header, string payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor, CancellationToken cancellationToken)
        {
            return await base.SignHttpRequestAsync(header, payload, signedHttpRequestDescriptor, cancellationToken).ConfigureAwait(false);
        }

        public string ConvertToJsonPublic(Dictionary<string, object> payload)
        {
            return base.ConvertToJson(payload);
        }

        public void AddAtClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            base.AddAtClaim(payload, signedHttpRequestDescriptor);
        }
   
        public void AddTsClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            AddTsClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddMClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            base.AddMClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddUClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            base.AddUClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddPClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            base.AddPClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddQClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            base.AddQClaim(payload, signedHttpRequestDescriptor);
        }
 
        public void AddHClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            base.AddHClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddBClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            base.AddBClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddNonceClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            base.AddNonceClaim(payload, signedHttpRequestDescriptor);
        }

        public async Task<SecurityToken> ValidateSignedHttpRequestPublicAsync(SecurityToken jwtSignedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await base.ValidateSignedHttpRequestAsync(jwtSignedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        public async Task ValidateSignedHttpRequestSignaturePublicAsync(SecurityToken jwtSignedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            await base.ValidateSignedHttpRequestSignatureAsync(jwtSignedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        public void ValidateTsClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            base.ValidateTsClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }
    
        public void ValidateMClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            base.ValidateMClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }

        public void ValidateUClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            base.ValidateUClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }

        public void ValidatePClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            base.ValidatePClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }
  
        public void ValidateQClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            base.ValidateQClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }
       
        public void ValidateHClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            base.ValidateHClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }

        public void ValidateBClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            base.ValidateBClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }

        public async Task<SecurityKey> ResolvePopKeyPublicAsync(SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await base.ResolvePopKeyAsync(validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        public string GetCnfClaimValuePublic(SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            return base.GetCnfClaimValue(validatedAccessToken, signedHttpRequestValidationContext);
        }

        public SecurityKey ResolvePopKeyFromJwkPublic(string jwk, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            return base.ResolvePopKeyFromJwk(jwk, signedHttpRequestValidationContext);
        }

        public async Task<SecurityKey> ResolvePopKeyFromJwePublicAsync(string jwe, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await base.ResolvePopKeyFromJweAsync(jwe, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }
      
        public async Task<SecurityKey> ResolvePopKeyFromJkuPublicAsync(string jkuSetUrl, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await base.ResolvePopKeyFromJkuAsync(jkuSetUrl, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }
       
        public async Task<SecurityKey> ResolvePopKeyFromJkuPublicAsync(string jkuSetUrl, string kid, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await base.ResolvePopKeyFromJkuAsync(jkuSetUrl, kid, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        public async Task<IList<SecurityKey>> GetPopKeysFromJkuPublicAsync(string jkuSetUrl, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await base.GetPopKeysFromJkuAsync(jkuSetUrl, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        public async Task<SecurityKey> ResolvePopKeyFromKeyIdentifierPublicAsync(string kid, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await base.ResolvePopKeyFromKeyIdentifierAsync(kid, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        #region Mock methods
        protected override void AddTsClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (signedHttpRequestDescriptor.CallContext.PropertyBag != null && signedHttpRequestDescriptor.CallContext.PropertyBag.TryGetValue("MockAddTsClaim", out object DateTimeNow))
            {
                if (payload == null)
                    throw LogHelper.LogArgumentNullException(nameof(payload));

                var signedHttpRequestCreationTime = ((DateTime)DateTimeNow).Add(signedHttpRequestDescriptor.SignedHttpRequestCreationPolicy.TimeAdjustment);
                payload.Add(SignedHttpRequestClaimTypes.Ts, (long)(signedHttpRequestCreationTime - EpochTime.UnixEpoch).TotalSeconds);
            }
            else
            {
                base.AddTsClaim(payload, signedHttpRequestDescriptor);
            }
        }

        protected override void ValidateTsClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateTsClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateTsClaimCall"] = true;
            else
                base.ValidateTsClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidateMClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateMClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateMClaimCall"] = true;
            else
                base.ValidateMClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidatePClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidatePClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidatePClaimCall"] = true;
            else
                base.ValidatePClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidateUClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateUClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateUClaimCall"] = true;
            else
                base.ValidateUClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidateQClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateQClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateQClaimCall"] = true;
            else
                base.ValidateQClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidateHClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateHClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateHClaimCall"] = true;
            else
                base.ValidateHClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidateBClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateBClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateBClaimCall"] = true;
            else
                base.ValidateBClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override async Task ValidateSignedHttpRequestSignatureAsync(SecurityToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockValidateSignedHttpRequestSignatureAsync"))
                return;
            else
                await base.ValidateSignedHttpRequestSignatureAsync(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<SecurityKey> ResolvePopKeyAsync(SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockResolvePopKeyAsync_returnValidKey"))
            {
                return SignedHttpRequestTestUtils.DefaultSigningCredentials.Key;
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockResolvePopKeyAsync_returnInvalidKey"))
            {
                return KeyingMaterial.RsaSecurityKey1;
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockResolvePopKeyAsync_returnNullKey"))
            {
                return null;
            }
            else
            {
                return await base.ResolvePopKeyAsync(validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            }
        }

        protected override async Task<TokenValidationResult> ValidateAccessTokenAsync(string accessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockValidateAccessTokenAsync_returnInvalidResult"))
            {
                return new TokenValidationResult()
                {
                    IsValid = false,
                    Exception = new SecurityTokenValidationException()
                };
            }
            else
            {
                return await base.ValidateAccessTokenAsync(accessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            }
        }

        protected override string GetCnfClaimValue(SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnJwk"))
            {
                return SignedHttpRequestTestUtils.DefaultCnfJwk.ToString(Formatting.None);
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnJwe"))
            {
                return SignedHttpRequestTestUtils.DefaultCnfJwe.ToString(Formatting.None);
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnJku"))
            {
                return SignedHttpRequestTestUtils.DefaultJku.ToString(Formatting.None);
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnJkuKid"))
            {
                return SignedHttpRequestTestUtils.DefaultJkuKid.ToString(Formatting.None);
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnKid"))
            {
                return SignedHttpRequestTestUtils.DefaultKid.ToString(Formatting.None);
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnCustom"))
            {
                return "{\"custom\": 1}";
            }
            else
            {
                return base.GetCnfClaimValue(validatedAccessToken, signedHttpRequestValidationContext);
            }
        }

        protected override SecurityKey ResolvePopKeyFromJwk(string jwk, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("trackResolvePopKeyFromJwk"))
            {
                signedHttpRequestValidationContext.CallContext.PropertyBag["trackResolvePopKeyFromJwk"] = true;
                return null;
            }

            return base.ResolvePopKeyFromJwk(jwk, signedHttpRequestValidationContext);  
        }

        protected override async Task<SecurityKey> ResolvePopKeyFromJweAsync(string jwe, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("trackResolvePopKeyFromJwe"))
            {
                signedHttpRequestValidationContext.CallContext.PropertyBag["trackResolvePopKeyFromJwe"] = true;
                return null;
            }

            return await base.ResolvePopKeyFromJweAsync(jwe, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jkuSetUrl, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("trackResolvePopKeyFromJku"))
            {
                signedHttpRequestValidationContext.CallContext.PropertyBag["trackResolvePopKeyFromJku"] = true;
                return null;
            }

            return await base.ResolvePopKeyFromJkuAsync(jkuSetUrl, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jkuSetUrl, string kid, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("trackResolvePopKeyFromJkuKid"))
            {
                signedHttpRequestValidationContext.CallContext.PropertyBag["trackResolvePopKeyFromJkuKid"] = true;
                return null;
            }

            return await base.ResolvePopKeyFromJkuAsync(jkuSetUrl, kid, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<SecurityKey> ResolvePopKeyFromKeyIdentifierAsync(string kid, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("trackResolvePopKeyFromKid"))
            {
                signedHttpRequestValidationContext.CallContext.PropertyBag["trackResolvePopKeyFromKid"] = true;
                return null;
            }

            return await base.ResolvePopKeyFromKeyIdentifierAsync(kid, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<IList<SecurityKey>> GetPopKeysFromJkuAsync(string jkuSetUrl, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetPopKeysFromJkuAsync_return0Keys"))
            {
                return new List<SecurityKey>();
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetPopKeysFromJkuAsync_returnNull"))
            {
                return null;
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetPopKeysFromJkuAsync_return2Keys"))
            {
                return new List<SecurityKey>()
                {
                    SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key,
                    SignedHttpRequestTestUtils.DefaultSigningCredentials.Key,
                };
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetPopKeysFromJkuAsync_return1Key"))
            {
                return new List<SecurityKey>()
                {
                    SignedHttpRequestTestUtils.DefaultSigningCredentials.Key
                };
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetPopKeysFromJkuAsync_returnWrongKey"))
            {
                return new List<SecurityKey>()
                {
                    SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key
                };
            }

            return await base.GetPopKeysFromJkuAsync(jkuSetUrl, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        #endregion
    }
}
