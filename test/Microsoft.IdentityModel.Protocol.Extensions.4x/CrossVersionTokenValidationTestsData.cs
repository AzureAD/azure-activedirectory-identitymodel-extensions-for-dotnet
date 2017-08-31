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
using System.ComponentModel;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace Microsoft.IdentityModel.Protocols.Extensions.OldVersion
{
    /// <summary>
    /// Tests for references in specs
    /// https://tools.ietf.org/html/rfc7518#appendix-A.3
    /// </summary>
    public class CrossVersionTokenValidationTestsData
    {
        public static SecurityToken GetSamlSecurityToken4x(SecurityTokenDescriptor descriptor)
        {
            return new Microsoft.IdentityModel.Tokens.SamlSecurityTokenHandler().CreateToken(descriptor);
        }

        public static ClaimsPrincipal GetSamlClaimsPrincipal4x(string securityToken, SharedTokenValidationParameters tokenValidationParameters, X509Certificate2 certificate, out System.IdentityModel.Tokens.SecurityToken validatedToken)
        {
            var tvp = new System.IdentityModel.Tokens.TokenValidationParameters();
            PropertyInfo[] propertyInfos = typeof(SharedTokenValidationParameters).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
            foreach (PropertyInfo propertyInfo in propertyInfos)
            {
                if (propertyInfo.GetMethod != null)
                {
                    object val = propertyInfo.GetValue(tokenValidationParameters, null);
                    PropertyInfo tvp4xPropertyInfo = typeof(System.IdentityModel.Tokens.TokenValidationParameters).GetProperty(propertyInfo.Name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
                    tvp4xPropertyInfo.SetValue(tvp, val);
                }
            }

            if (certificate != null)
                tvp.IssuerSigningKey = new System.IdentityModel.Tokens.X509SecurityKey(certificate);

            return new Microsoft.IdentityModel.Tokens.SamlSecurityTokenHandler().ValidateToken(securityToken, tvp, out validatedToken);
        }

        public static string GetSamlToken(SecurityToken token)
        {
            StringBuilder sb = new StringBuilder();
            XmlWriter writer = XmlWriter.Create(sb);
            new Microsoft.IdentityModel.Tokens.SamlSecurityTokenHandler().WriteToken(writer, token);
            writer.Flush();
            writer.Close();
            return sb.ToString();
        }
    }

    public class SharedTokenValidationParameters
    {
        public TimeSpan ClockSkew { get; set; }
        public string NameClaimType { get; set; }
        public bool RequireExpirationTime { get; set; }
        public bool RequireSignedTokens { get; set; }
        public string RoleClaimType { get; set; }
        public bool SaveSigninToken { get; set; }
        [DefaultValue(false)]
        public bool ValidateActor { get; set; }
        [DefaultValue(true)]
        public bool ValidateAudience { get; set; }
        [DefaultValue(true)]
        public bool ValidateIssuer { get; set; }
        public bool ValidateIssuerSigningKey { get; set; }
        [DefaultValue(true)]
        public bool ValidateLifetime { get; set; }
        public string ValidAudience { get; set; }
        public IEnumerable<string> ValidAudiences { get; set; }
        public string ValidIssuer { get; set; }
        public IEnumerable<string> ValidIssuers { get; set; }
    }
}
