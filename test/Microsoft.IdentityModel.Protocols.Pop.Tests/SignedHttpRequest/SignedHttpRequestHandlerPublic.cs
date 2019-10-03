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
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.Pop.SignedHttpRequest;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.Pop.Tests.SignedHttpRequest
{
    /// <summary>
    /// Mock SignedHttpRequestHandler.
    /// </summary>
    public class SignedHttpRequestHandlerPublic : SignedHttpRequestHandler
    {
        public string CreateHttpRequestHeaderPublic(SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            return base.CreateHttpRequestHeader(signedHttpRequestCreationData);
        }

        public string CreateHttpRequestPayloadPublic(SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            return base.CreateHttpRequestPayload(signedHttpRequestCreationData);
        }

        public async Task<string> SignHttpRequestPublicAsync(string header, string payload, SignedHttpRequestCreationData signedHttpRequestCreationData, CancellationToken cancellationToken)
        {
            return await base.SignHttpRequestAsync(header, payload, signedHttpRequestCreationData, cancellationToken).ConfigureAwait(false);
        }

        public string ConvertToJsonPublic(Dictionary<string, object> payload)
        {
            return base.ConvertToJson(payload);
        }

        public void AddAtClaimPublic(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            base.AddAtClaim(payload, signedHttpRequestCreationData);
        }
   
        public void AddTsClaimPublic(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            AddTsClaim(payload, signedHttpRequestCreationData);
        }

        public void AddMClaimPublic(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            base.AddMClaim(payload, signedHttpRequestCreationData);
        }

        public void AddUClaimPublic(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            base.AddUClaim(payload, signedHttpRequestCreationData);
        }

        public void AddPClaimPublic(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            base.AddPClaim(payload, signedHttpRequestCreationData);
        }

        public void AddQClaimPublic(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            base.AddQClaim(payload, signedHttpRequestCreationData);
        }
 
        public void AddHClaimPublic(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            base.AddHClaim(payload, signedHttpRequestCreationData);
        }

        public void AddBClaimPublic(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            base.AddBClaim(payload, signedHttpRequestCreationData);
        }

        public void AddNonceClaimPublic(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            base.AddNonceClaim(payload, signedHttpRequestCreationData);
        }

        public async Task<SecurityToken> ValidateSignedHttpRequestPublicAsync(SecurityToken jwtSignedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            return await base.ValidateSignedHttpRequestAsync(jwtSignedHttpRequest, validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
        }

        public async Task ValidateSignedHttpRequestSignaturePublicAsync(SecurityToken jwtSignedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            await base.ValidateSignedHttpRequestSignatureAsync(jwtSignedHttpRequest, validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
        }

        public void ValidateTsClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            base.ValidateTsClaim(jwtSignedHttpRequest, signedHttpRequestValidationData);
        }
    
        public void ValidateMClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            base.ValidateMClaim(jwtSignedHttpRequest, signedHttpRequestValidationData);
        }

        public void ValidateUClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            base.ValidateUClaim(jwtSignedHttpRequest, signedHttpRequestValidationData);
        }

        public void ValidatePClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            base.ValidatePClaim(jwtSignedHttpRequest, signedHttpRequestValidationData);
        }
  
        public void ValidateQClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            base.ValidateQClaim(jwtSignedHttpRequest, signedHttpRequestValidationData);
        }
       
        public void ValidateHClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            base.ValidateHClaim(jwtSignedHttpRequest, signedHttpRequestValidationData);
        }

        public void ValidateBClaimPublic(SecurityToken jwtSignedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            base.ValidateBClaim(jwtSignedHttpRequest, signedHttpRequestValidationData);
        }

        public async Task<SecurityKey> ResolvePopKeyPublicAsync(SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            return await base.ResolvePopKeyAsync(validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
        }

        public string GetCnfClaimValuePublic(SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            return base.GetCnfClaimValue(validatedAccessToken, signedHttpRequestValidationData);
        }

        public SecurityKey ResolvePopKeyFromJwkPublic(string jwk, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            return base.ResolvePopKeyFromJwk(jwk, signedHttpRequestValidationData);
        }

        public async Task<SecurityKey> ResolvePopKeyFromJwePublicAsync(string jwe, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            return await base.ResolvePopKeyFromJweAsync(jwe, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
        }
      
        public async Task<SecurityKey> ResolvePopKeyFromJkuPublicAsync(string jkuSetUrl, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            return await base.ResolvePopKeyFromJkuAsync(jkuSetUrl, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
        }
       
        public async Task<SecurityKey> ResolvePopKeyFromJkuPublicAsync(string jkuSetUrl, string kid, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            return await base.ResolvePopKeyFromJkuAsync(jkuSetUrl, kid, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
        }

        public async Task<IList<SecurityKey>> GetPopKeysFromJkuPublicAsync(string jkuSetUrl, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            return await base.GetPopKeysFromJkuAsync(jkuSetUrl, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
        }

        public async Task<SecurityKey> ResolvePopKeyFromKeyIdentifierPublicAsync(string kid, SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            return await base.ResolvePopKeyFromKeyIdentifierAsync(kid, validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
        }

        #region Mock methods
        protected override void AddTsClaim(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            if (signedHttpRequestCreationData.CallContext.PropertyBag != null && signedHttpRequestCreationData.CallContext.PropertyBag.TryGetValue("MockAddTsClaim", out object DateTimeNow))
            {
                if (payload == null)
                    throw LogHelper.LogArgumentNullException(nameof(payload));

                var signedHttpRequestCreationTime = ((DateTime)DateTimeNow).Add(signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.TimeAdjustment);
                payload.Add(Pop.PopConstants.SignedHttpRequest.ClaimTypes.Ts, (long)(signedHttpRequestCreationTime - EpochTime.UnixEpoch).TotalSeconds);
            }
            else
            {
                base.AddTsClaim(payload, signedHttpRequestCreationData);
            }
        }

        protected override void ValidateTsClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateTsClaimCall"))
                signedHttpRequestValidationData.CallContext.PropertyBag["onlyTrack_ValidateTsClaimCall"] = true;
            else
                base.ValidateTsClaim(signedHttpRequest, signedHttpRequestValidationData);
        }

        protected override void ValidateMClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateMClaimCall"))
                signedHttpRequestValidationData.CallContext.PropertyBag["onlyTrack_ValidateMClaimCall"] = true;
            else
                base.ValidateMClaim(signedHttpRequest, signedHttpRequestValidationData);
        }

        protected override void ValidatePClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidatePClaimCall"))
                signedHttpRequestValidationData.CallContext.PropertyBag["onlyTrack_ValidatePClaimCall"] = true;
            else
                base.ValidatePClaim(signedHttpRequest, signedHttpRequestValidationData);
        }

        protected override void ValidateUClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateUClaimCall"))
                signedHttpRequestValidationData.CallContext.PropertyBag["onlyTrack_ValidateUClaimCall"] = true;
            else
                base.ValidateUClaim(signedHttpRequest, signedHttpRequestValidationData);
        }

        protected override void ValidateQClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateQClaimCall"))
                signedHttpRequestValidationData.CallContext.PropertyBag["onlyTrack_ValidateQClaimCall"] = true;
            else
                base.ValidateQClaim(signedHttpRequest, signedHttpRequestValidationData);
        }

        protected override void ValidateHClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateHClaimCall"))
                signedHttpRequestValidationData.CallContext.PropertyBag["onlyTrack_ValidateHClaimCall"] = true;
            else
                base.ValidateHClaim(signedHttpRequest, signedHttpRequestValidationData);
        }

        protected override void ValidateBClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateBClaimCall"))
                signedHttpRequestValidationData.CallContext.PropertyBag["onlyTrack_ValidateBClaimCall"] = true;
            else
                base.ValidateBClaim(signedHttpRequest, signedHttpRequestValidationData);
        }

        protected override async Task ValidateSignedHttpRequestSignatureAsync(SecurityToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("mockValidateSignedHttpRequestSignatureAsync"))
                return;
            else
                await base.ValidateSignedHttpRequestSignatureAsync(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<SecurityKey> ResolvePopKeyAsync(SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("mockResolvePopKeyAsync_returnValidKey"))
            {
                return SignedHttpRequestTestUtils.DefaultSigningCredentials.Key;
            }
            else if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("mockResolvePopKeyAsync_returnInvalidKey"))
            {
                return KeyingMaterial.RsaSecurityKey1;
            }
            else if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("mockResolvePopKeyAsync_returnNullKey"))
            {
                return null;
            }
            else
            {
                return await base.ResolvePopKeyAsync(validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
            }
        }

        protected override async Task<TokenValidationResult> ValidateAccessTokenAsync(string accessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationData.CallContext.PropertyBag != null && signedHttpRequestValidationData.CallContext.PropertyBag.ContainsKey("mockValidateAccessTokenAsync_returnInvalidResult"))
            {
                return new TokenValidationResult()
                {
                    IsValid = false,
                    Exception = new SecurityTokenValidationException()
                };
            }
            else
            {
                return await base.ValidateAccessTokenAsync(accessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
            }
        }

        #endregion
    }
}
