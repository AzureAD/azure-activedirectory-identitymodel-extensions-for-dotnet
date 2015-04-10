//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System;
using System.Diagnostics.Tracing;
using System.Globalization;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Extensions
{
    /// <summary>
    /// 
    /// </summary>
    internal static class IssuerValidator
    {
        public static string Validate(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            IdentityModelEventSource.Logger.WriteInformation("validating issuers in the jwt token");
            if (validationParameters == null)
            {
                LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, "validationParameters"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (string.IsNullOrWhiteSpace(issuer))
            {
                LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10211), typeof(SecurityTokenInvalidIssuerException), EventLevel.Verbose);
            }

            // Throw if all possible places to validate against are null or empty
            if (string.IsNullOrWhiteSpace(validationParameters.ValidIssuer) && (validationParameters.ValidIssuers == null))
            {
                LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10204), typeof(SecurityTokenInvalidIssuerException));
            }

            if (!string.IsNullOrWhiteSpace(validationParameters.ValidIssuer) && string.Equals(validationParameters.ValidIssuer, issuer, StringComparison.Ordinal))
            {
                return issuer;
            }

            if (null != validationParameters.ValidIssuers)
            {
                foreach (string str in validationParameters.ValidIssuers)
                {
                    if (string.Equals(str, issuer, StringComparison.Ordinal))
                    {
                        return issuer;
                    }
                }
            }

            string validIssuer = validationParameters.ValidIssuer ?? "null";
            string validIssuers = "null";
            if (validationParameters.ValidIssuers != null)
            {
                bool first = true;
                foreach (string str in validationParameters.ValidIssuers)
                {
                    if (!string.IsNullOrWhiteSpace(str))
                    {
                        validIssuers += str;
                        if (!first)
                        {
                            validIssuers += ", ";
                        }
                        first = false;
                    }
                }
            }

            LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10205, validIssuer, validIssuers, issuer), typeof(SecurityTokenInvalidIssuerException));
            return null;
        }
    }
}
