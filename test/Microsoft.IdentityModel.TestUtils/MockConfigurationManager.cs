﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.TestUtils
{
    /// <summary>
    /// This type is used for testing the functionality of using a last known good configuration, as well
    /// as a refreshed configuration.
    /// </summary>
    /// <typeparam name="T">must be a class.</typeparam>
    public class MockConfigurationManager<T> : BaseConfigurationManager, IConfigurationManager<T> where T : class
    {
        private T _configuration;
        private T _refreshedConfiguration;

        /// <summary>
        /// Initializes an new instance of <see cref="MockConfigurationManager{T}"/> with a Configuration instance.
        /// </summary>
        /// <param name="configuration">Configuration of type OpenIdConnectConfiguration or OpenIdConnectConfiguration.</param>
        public MockConfigurationManager(T configuration)
        {
            if (configuration == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(configuration)));

            _configuration = configuration;
        }

        /// <summary>
        /// Initializes an new instance of <see cref="MockConfigurationManager{T}"/> with a Configuration instance and a LKG Configuration instance.
        /// </summary>
        /// <param name="configuration">Configuration of type OpenIdConnectConfiguration or OpenIdConnectConfiguration.</param>
        /// <param name="lkgConfiguration">Configuration of type OpenIdConnectConfiguration or OpenIdConnectConfiguration.</param>
        public MockConfigurationManager(T configuration, T lkgConfiguration) : this(configuration)
        {
            if (lkgConfiguration == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(lkgConfiguration)));

            LastKnownGoodConfiguration = lkgConfiguration as BaseConfiguration;
        }

        /// <summary>
        /// Initializes an new instance of <see cref="MockConfigurationManager{T}"/> with a Configuration instance and a LKG Configuration instance.
        /// </summary>
        /// <param name="configuration">Configuration of type OpenIdConnectConfiguration or WsFederationConfiguration.</param>
        /// <param name="lkgConfiguration">Configuration of type OpenIdConnectConfiguration or WsFederationConfiguration.</param>
        /// <param name="refreshedConfiguration">The configuration to return after RequestRefresh() is called.</param>
        public MockConfigurationManager(T configuration, T lkgConfiguration, T refreshedConfiguration) : this(configuration, lkgConfiguration)
        {
            if (refreshedConfiguration == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(refreshedConfiguration)));

            _refreshedConfiguration = refreshedConfiguration;
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
        /// Obtains an updated version of Configuration.
        /// </summary>
        /// <param name="cancel"><see cref="CancellationToken"/>.</param>
        /// <returns>Configuration of type T.</returns>
        public override Task<BaseConfiguration> GetBaseConfigurationAsync(CancellationToken cancel)
        {
            return Task.FromResult(_configuration as BaseConfiguration);
        }

        /// <summary>
        /// Unless _refreshedConfiguration is set, this is a no-op.
        /// </summary>
        public override void RequestRefresh()
        {
            if (_refreshedConfiguration != null && _refreshedConfiguration != _configuration)
                _configuration = _refreshedConfiguration;
        }
    }
}

