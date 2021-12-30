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
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Configuration
{
    /// <summary>
    /// Validates OpenIdConnectConfiguration.
    /// </summary>
    public class OpenIdConnectConfigurationValidationExecutor : Protocols.Configuration.IConfigurationValidationExecutor<OpenIdConnectConfiguration>
    {
        /// <summary>
        /// Additional OpenIdConfiguration Validators.
        /// </summary>
        public List<IConfigurationValidator<OpenIdConnectConfiguration>> AdditionalOpenIdConnectConfigurationValidators { get; }

        /// <summary>
        /// Default OpenIdConfiguration Validator.
        /// </summary>
        public IConfigurationValidator<OpenIdConnectConfiguration> DefaultOpenIdConnectConfigurationValidator { get; } = new OpenIdConnectConfigurationValidator();

        /// <summary>
        /// Validates a OpenIdConnectConfiguration by using current validator.
        /// </summary>
        /// <param name="openIdConnectConfiguration">The OpenIdConnectConfiguration to validate.</param>
        public void ValidateConfiguration(OpenIdConnectConfiguration openIdConnectConfiguration)
        {
            if (openIdConnectConfiguration == null)
                throw new ArgumentNullException(nameof(openIdConnectConfiguration));

            var allValidators = new List<IConfigurationValidator<OpenIdConnectConfiguration>>
            {
                DefaultOpenIdConnectConfigurationValidator
            };

            var exceptions = new List<ConfigurationValidationException>();

            if (AdditionalOpenIdConnectConfigurationValidators != null)
                allValidators.AddRange(AdditionalOpenIdConnectConfigurationValidators);

            foreach (IConfigurationValidator<OpenIdConnectConfiguration> validator in allValidators)
            {
                ConfigurationValidationResult result = validator.Validate(openIdConnectConfiguration);
                if (!result.Succeeded)
                {
                    exceptions.Add(result.Exception);
                }
            }

            if (exceptions.Any())
                throw new ConfigurationValidationException("Invalid configuraiton", new AggregateException(exceptions));
        }
    }
}
