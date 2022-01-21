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
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Validates configuration by using validator.
    /// </summary>
    /// <typeparam name="T">The type of the configuration.</typeparam>
    public class ConfigurationValidationExecutor<T> where T : class
    {
        /// <summary>
        /// Instantiates a new <see cref="ConfigurationValidationExecutor{T}"/> that validate retrived configuration data.
        /// </summary>
        /// <param name="defaultConfigurationValidator">The default configuration validator.</param>
        public ConfigurationValidationExecutor(IConfigurationValidator<T> defaultConfigurationValidator)
        {
            DefaultConfigurationValidator = defaultConfigurationValidator ?? throw LogHelper.LogArgumentNullException(nameof(defaultConfigurationValidator));
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationValidationExecutor{T}"/> that validate retrived configuration data.
        /// </summary>
        /// <param name="defaultConfigurationValidator">The default configuration validator.</param>
        /// <param name="additionalConfigurationValidator">The additional configuration validator.</param>
        public ConfigurationValidationExecutor(IConfigurationValidator<T> defaultConfigurationValidator, IConfigurationValidator<T> additionalConfigurationValidator)
            : this(defaultConfigurationValidator)
        {
            //DefaultConfigurationValidator = defaultConfigurationValidator ?? throw LogHelper.LogArgumentNullException(nameof(defaultConfigurationValidator));
            AdditionalConfigurationValidator = additionalConfigurationValidator ?? throw LogHelper.LogArgumentNullException(nameof(additionalConfigurationValidator));
        }

        /// <summary>
        /// Additional Configuration Validator.
        /// </summary>
        public IConfigurationValidator<T> AdditionalConfigurationValidator { get; }

        /// <summary>
        /// Default Configuration Validator.
        /// </summary>
        public IConfigurationValidator<T> DefaultConfigurationValidator { get; }

        /// <summary>
        /// Indicates whether the configuration should be validated, false by default.
        /// </summary>
        [DefaultValue(false)]
        public bool ShouldValidateConfiguration { get; set; } = false;

        /// <summary>
        /// Validates a OpenIdConnectConfiguration by using current validator.
        /// </summary>
        /// <param name="configuration">The configuration to validate.</param>
        public void ValidateConfiguration(T configuration)
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            var allValidators = new List<IConfigurationValidator<T>>
            {
                DefaultConfigurationValidator
            };

            var exceptions = new List<ConfigurationValidationException>();

            if (AdditionalConfigurationValidator != null)
                allValidators.Add(AdditionalConfigurationValidator);

            foreach (IConfigurationValidator<T> validator in allValidators)
            {
                ConfigurationValidationResult result = validator.Validate(configuration);
                if (!result.Succeeded)
                {
                    //exceptions.Add(result.Exception);
                    throw new ConfigurationValidationException(LogMessages.IDX20810, result.Exception);
                }
            }

            //if (exceptions.Any())
                //throw new ConfigurationValidationException(LogMessages.IDX20810, new AggregateException(exceptions));
        }
    }
}
