using Microsoft.IdentityModel.Protocols;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Extensions
{
    public class OpenIdConnectProtocolValidator
    {
        private static readonly RNGCryptoServiceProvider Random;
        private static char base64PadCharacter = '=';
        private static char base64Character62 = '+';
        private static char base64Character63 = '/';
        private static char base64UrlCharacter62 = '-';
        private static char base64UrlCharacter63 = '_';

        static OpenIdConnectProtocolValidator()
        {
            Random = new RNGCryptoServiceProvider();
        }

        public virtual string GetNonce() 
        { 
            return Guid.NewGuid().ToString() + Guid.NewGuid().ToString(); 
        }

        public virtual bool ValidateAudience(IEnumerable<string> audiences, TokenValidationParameters validationParameters, SecurityToken securityToken)
        {
            return true;
        }

        public virtual void ValidateCHash(JwtSecurityToken jwt, string authorizationCode)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException("jwt");
            }

            if (string.IsNullOrWhiteSpace(authorizationCode))
            {
                throw new ArgumentNullException("authorizationCode");
            }

            // validate the Hash(oir.Code) == jwt.CodeClaim
            // When a response_type is id_token + code, the code must == a special hash of a claim inside the token.
            // Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the 'code'. 
            // where the hash algorithm used is the hash algorithm used in the alg parameter of the ID Token's JWS 
            // For instance, if the alg is RS256, hash the access_token value with SHA-256, then take the left-most 128 bits and base64url encode them.

            HashAlgorithm hashAlgorithm = null;
            if (!jwt.Payload.ContainsKey(JwtConstants.ReservedClaims.CHash))
            {
                throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10308, JwtConstants.ReservedClaims.CHash, jwt.RawData ?? string.Empty));
            }

            string c_hashInToken = jwt.Payload[JwtConstants.ReservedClaims.CHash] as string;
            if (c_hashInToken == null)
            {                
                throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10302, jwt.RawData ?? string.Empty));
            }

            if (string.IsNullOrEmpty(c_hashInToken))
            {                
                throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10303, jwt.RawData ?? string.Empty));
            }

            string algorithm = string.Empty;
            if (!jwt.Header.TryGetValue(JwtConstants.ReservedHeaderParameters.Alg, out algorithm))
            {
                algorithm = JwtConstants.Algorithms.RSA_SHA256;
            }


            JwtSecurityTokenHandler.InboundAlgorithmMap.TryGetValue(algorithm, out algorithm);
            try
            {
                try
                {
                    hashAlgorithm = HashAlgorithm.Create(algorithm);
                }
                catch (Exception ex)
                {
                    throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10306, algorithm, jwt.RawData ?? string.Empty), ex);
                }

                if (hashAlgorithm == null)
                {
                    throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10306, algorithm, jwt.RawData ?? string.Empty));
                }

                byte[] hashBytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(authorizationCode));
                string hashString = Convert.ToBase64String(hashBytes, 0, hashBytes.Length / 2);
                hashString = hashString.Split(base64PadCharacter)[0]; // Remove any trailing padding
                hashString = hashString.Replace(base64Character62, base64UrlCharacter62); // 62nd char of encoding
                hashString = hashString.Replace(base64Character63, base64UrlCharacter63); // 63rd char of encoding

                if (!StringComparer.Ordinal.Equals(c_hashInToken, hashString))
                {
                    throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10304, c_hashInToken, authorizationCode, algorithm, jwt.RawData ?? string.Empty));
                }
            }
            finally
            {
                if (hashAlgorithm != null)
                {
                    hashAlgorithm.Dispose();
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="nonce"></param>
        /// <returns></returns>
        public virtual void ValidateNonce(JwtSecurityToken jwt, string nonce)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException("jwt");
            }

            if (string.IsNullOrWhiteSpace(nonce))
            {
                throw new ArgumentNullException("nonce");
            }

            string nonceFoundInJwt = jwt.Payload.Nonce;
            if (nonceFoundInJwt == null || string.IsNullOrWhiteSpace(nonceFoundInJwt))
            {
                string message = string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10300, JwtConstants.ReservedClaims.Nonce, jwt.RawData ?? string.Empty);
                throw new OpenIdConnectProtocolInvalidNonceException(message);
            }

            if (!(StringComparer.Ordinal.Equals(nonceFoundInJwt, nonce)))
            {
                string message = string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10301, nonceFoundInJwt, nonce);
                throw new OpenIdConnectProtocolException(message);
            }
        }
    }
}
