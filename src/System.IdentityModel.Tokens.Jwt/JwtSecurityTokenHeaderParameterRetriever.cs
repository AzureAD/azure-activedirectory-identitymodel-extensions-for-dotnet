// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace System.IdentityModel.Tokens.Jwt
{
    internal class JwtSecurityTokenHeaderParameterRetriever : IHeaderParameterRetriever
    {
        private readonly JwtHeader _header;

        /// <summary>
        /// Creates an instance of a <see cref="JwtSecurityTokenHeaderParameterRetriever"/>
        /// </summary>
        /// <param name="header">The <see cref="JwtHeader"/> to create the <see cref="JwtSecurityTokenHeaderParameterRetriever"/> from.</param>
        public JwtSecurityTokenHeaderParameterRetriever(JwtHeader header)
        {
            _header = header ?? throw LogHelper.LogArgumentNullException(nameof(header));
        }

        /// <inheritdoc/>
        public string GetHeaderParameter(string parameter)
        {
            if (string.IsNullOrEmpty(parameter))
                throw LogHelper.LogArgumentNullException(nameof(parameter));

            return _header.GetStandardClaim(parameter) ?? string.Empty;
        }
    }
}
