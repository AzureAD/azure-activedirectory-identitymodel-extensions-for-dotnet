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
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// This type is for users that want a fixed and static Configuration.
    /// In this case, the configuration is obtained and passed to the constructor.
    /// </summary>
    /// <typeparam name="T">must be a class.</typeparam>
    public class StaticConfigurationManager<T> : IConfigurationManager<T> where T : class
    {
        private T _configuration;

        /// <summary>
        /// Initializes an new instance of <see cref="StaticConfigurationManager"/> with a Configuration instance.
        /// </summary>
        /// <param name="configuration">Configuration of type <see cref="OpenIdConnectConfiguration"/> or <see cref="WsFederationConfiguration"/>.</param>
        public StaticConfigurationManager(T configuration)
        {
            if (configuration == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": configuration"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            _configuration = configuration;
        }

        /// <summary>
        /// Obtains an updated version of Configuration.
        /// </summary>
        /// <param name="cancel"><see cref="CancellationToken"/>.</param>
        /// <returns>Configuration of type T.</returns>
        public Task<T> GetConfigurationAsync(CancellationToken cancel)
        {
            return Task.FromResult(_configuration);
        }

        /// <summary>
        /// For the this type, this is a no-op
        /// </summary>
        public void RequestRefresh()
        {
        }
    }
}
