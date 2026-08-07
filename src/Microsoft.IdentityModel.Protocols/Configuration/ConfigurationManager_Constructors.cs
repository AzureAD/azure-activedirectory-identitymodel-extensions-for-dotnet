// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Net.Http;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols;

/// <summary>
/// Constructors and factory methods for <see cref="ConfigurationManager{T}"/>.
/// </summary>
// CA1000: the CreateSync factory methods are intentionally static on this generic type. They provide a
// synchronous-only construction path whose parameters are typed on the synchronous retriever interfaces
// (IConfigurationRetrieverSync<T>/IDocumentRetrieverSync); exposing them as constructors would collide with the
// existing asynchronous constructors (CS0121) because the provided retrievers in this repo (OpenIdConnectConfigurationRetriever and
// WsFederationConfigurationRetriever / HttpDocumentRetriever and FileDocumentRetriever) implement both the sync and async interfaces.
[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1000:DoNotDeclareStaticMembersOnGenericTypes")]
public partial class ConfigurationManager<T> : BaseConfigurationManager, IConfigurationManager<T>, IConfigurationManagerSync<T> where T : class
{
    /// <summary>
    /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
    public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever)
        : this(metadataAddress, configRetriever, new HttpDocumentRetriever(), new LastKnownGoodConfigurationCacheOptions())
    {
    }

    /// <summary>
    /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
    /// <param name="httpClient">The client to use when obtaining configuration.</param>
    public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, HttpClient httpClient)
        : this(metadataAddress, configRetriever, new HttpDocumentRetriever(httpClient), new LastKnownGoodConfigurationCacheOptions())
    {
    }

    /// <summary>
    /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
    /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
    /// <exception cref="ArgumentNullException">If 'metadataAddress' is null or empty.</exception>
    /// <exception cref="ArgumentNullException">If 'configRetriever' is null.</exception>
    /// <exception cref="ArgumentNullException">If 'docRetriever' is null.</exception>
    public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, IDocumentRetriever docRetriever)
        : this(metadataAddress, configRetriever, docRetriever, new LastKnownGoodConfigurationCacheOptions())
    {
    }

    /// <summary>
    /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
    /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
    /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/></param>
    /// <exception cref="ArgumentNullException">If 'metadataAddress' is null or empty.</exception>
    /// <exception cref="ArgumentNullException">If 'configRetriever' is null.</exception>
    /// <exception cref="ArgumentNullException">If 'docRetriever' is null.</exception>
    /// <exception cref="ArgumentNullException">If 'lkgCacheOptions' is null.</exception>
    /// <remarks>
    /// This constructor enables only the asynchronous retrieval pipeline. To enable synchronous retrieval, use
    /// <see cref="CreateSync(string, IConfigurationRetrieverSync{T}, IDocumentRetrieverSync)"/>.
    /// </remarks>
    public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, IDocumentRetriever docRetriever, LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
        : base(lkgCacheOptions)
    {
        if (string.IsNullOrWhiteSpace(metadataAddress))
            throw LogHelper.LogArgumentNullException(nameof(metadataAddress));

        if (configRetriever == null)
            throw LogHelper.LogArgumentNullException(nameof(configRetriever));

        if (docRetriever == null)
            throw LogHelper.LogArgumentNullException(nameof(docRetriever));

        MetadataAddress = metadataAddress;
        _docRetrieverAsync = docRetriever;
        _configRetrieverAsync = configRetriever;
        _preferSynchronousRetrieval = false;

        _updateCurrentConfigurationWithBypassAsync = () => UpdateCurrentConfigurationAsync(bypassCache: true);
        _updateCurrentConfigurationWithoutBypassAsync = () => UpdateCurrentConfigurationAsync(bypassCache: false);
        _updateCurrentConfigurationWithBypassSync = () => UpdateCurrentConfigurationSync(bypassCache: true);
        _updateCurrentConfigurationWithoutBypassSync = () => UpdateCurrentConfigurationSync(bypassCache: false);
    }

    /// <summary>
    /// Instantiates a new <see cref="ConfigurationManager{T}"/> with configuration validator that manages automatic and controls refreshing on configuration data.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
    /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
    /// <param name="configValidator">The <see cref="IConfigurationValidator{T}"/></param>
    /// <exception cref="ArgumentNullException">If 'configValidator' is null.</exception>
    public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, IDocumentRetriever docRetriever, IConfigurationValidator<T> configValidator)
        : this(metadataAddress, configRetriever, docRetriever, configValidator, new LastKnownGoodConfigurationCacheOptions())
    {
    }

    /// <summary>
    /// Instantiates a new <see cref="ConfigurationManager{T}"/> with configuration validator that manages automatic and controls refreshing on configuration data.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
    /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
    /// <param name="configValidator">The <see cref="IConfigurationValidator{T}"/></param>
    /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/></param>
    /// <exception cref="ArgumentNullException">If 'configValidator' is null.</exception>
    public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, IDocumentRetriever docRetriever, IConfigurationValidator<T> configValidator, LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
        : this(metadataAddress, configRetriever, docRetriever, lkgCacheOptions)
    {
        if (configValidator == null)
            throw LogHelper.LogArgumentNullException(nameof(configValidator));

        _configValidator = configValidator;
    }

    /// <summary>
    /// Instantiates a new <see cref="ConfigurationManager{T}"/> with configuration validator that manages automatic and controls refreshing on configuration data.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/>.</param>
    /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
    /// <param name="configValidator">The <see cref="IConfigurationValidator{T}"/>.</param>
    /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/>.</param>
    /// <param name="configurationEventHandler">The <see cref="IConfigurationEventHandler{T}"/> that handles configuration events.</param>
    /// <exception cref="ArgumentNullException">If 'configValidator' is null.</exception>
    public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, IDocumentRetriever docRetriever, IConfigurationValidator<T> configValidator, LastKnownGoodConfigurationCacheOptions lkgCacheOptions, IConfigurationEventHandler<T> configurationEventHandler)
        : this(metadataAddress, configRetriever, docRetriever, configValidator, lkgCacheOptions)
    {
        if (configurationEventHandler == null)
            throw LogHelper.LogArgumentNullException(nameof(configurationEventHandler));

        ConfigurationEventHandler = configurationEventHandler;
    }

    /// <summary>
    /// Private base constructor for the synchronous-only construction path.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetrieverSync{T}"/>.</param>
    /// <param name="docRetriever">The <see cref="IDocumentRetrieverSync"/> that reaches out to obtain the configuration.</param>
    /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/>.</param>
    /// <exception cref="ArgumentNullException">If 'metadataAddress' is null or empty.</exception>
    /// <exception cref="ArgumentNullException">If 'configRetriever' is null.</exception>
    /// <exception cref="ArgumentNullException">If 'docRetriever' is null.</exception>
    /// <exception cref="ArgumentNullException">If 'lkgCacheOptions' is null.</exception>
    private ConfigurationManager(string metadataAddress, IConfigurationRetrieverSync<T> configRetriever, IDocumentRetrieverSync docRetriever, LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
        : base(lkgCacheOptions)
    {
        if (string.IsNullOrWhiteSpace(metadataAddress))
            throw LogHelper.LogArgumentNullException(nameof(metadataAddress));

        if (configRetriever == null)
            throw LogHelper.LogArgumentNullException(nameof(configRetriever));

        if (docRetriever == null)
            throw LogHelper.LogArgumentNullException(nameof(docRetriever));

        MetadataAddress = metadataAddress;
        _docRetrieverSync = docRetriever;
        _configRetrieverSync = configRetriever;
        _preferSynchronousRetrieval = true;

        _updateCurrentConfigurationWithBypassAsync = () => UpdateCurrentConfigurationAsync(bypassCache: true);
        _updateCurrentConfigurationWithoutBypassAsync = () => UpdateCurrentConfigurationAsync(bypassCache: false);
        _updateCurrentConfigurationWithBypassSync = () => UpdateCurrentConfigurationSync(bypassCache: true);
        _updateCurrentConfigurationWithoutBypassSync = () => UpdateCurrentConfigurationSync(bypassCache: false);
    }

    /// <summary>
    /// Private constructor for the synchronous-only construction path that additionally attaches a configuration validator.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetrieverSync{T}"/>.</param>
    /// <param name="docRetriever">The <see cref="IDocumentRetrieverSync"/> that reaches out to obtain the configuration.</param>
    /// <param name="configValidator">The <see cref="IConfigurationValidator{T}"/>.</param>
    /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/>.</param>
    /// <exception cref="ArgumentNullException">If 'configValidator' is null.</exception>
    private ConfigurationManager(string metadataAddress, IConfigurationRetrieverSync<T> configRetriever, IDocumentRetrieverSync docRetriever, IConfigurationValidator<T> configValidator, LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
        : this(metadataAddress, configRetriever, docRetriever, lkgCacheOptions)
    {
        if (configValidator == null)
            throw LogHelper.LogArgumentNullException(nameof(configValidator));

        _configValidator = configValidator;
    }

    /// <summary>
    /// Creates a <see cref="ConfigurationManager{T}"/> backed by the synchronous retrieval contracts.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetrieverSync{T}"/>.</param>
    /// <param name="docRetriever">The <see cref="IDocumentRetrieverSync"/> that reaches out to obtain the configuration.</param>
    /// <returns>A <see cref="ConfigurationManager{T}"/> whose synchronous pipeline is enabled.</returns>
    /// <remarks>The returned manager enables only the synchronous retrieval pipeline.</remarks>
    /// <exception cref="ArgumentNullException">If 'metadataAddress' is null or empty.</exception>
    /// <exception cref="ArgumentNullException">If 'configRetriever' is null.</exception>
    /// <exception cref="ArgumentNullException">If 'docRetriever' is null.</exception>
    public static ConfigurationManager<T> CreateSync(string metadataAddress, IConfigurationRetrieverSync<T> configRetriever, IDocumentRetrieverSync docRetriever)
    {
        return new ConfigurationManager<T>(metadataAddress, configRetriever, docRetriever, new LastKnownGoodConfigurationCacheOptions());
    }

    /// <summary>
    /// Creates a <see cref="ConfigurationManager{T}"/> backed by the synchronous retrieval contracts.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetrieverSync{T}"/>.</param>
    /// <param name="docRetriever">The <see cref="IDocumentRetrieverSync"/> that reaches out to obtain the configuration.</param>
    /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/>.</param>
    /// <returns>A <see cref="ConfigurationManager{T}"/> whose synchronous pipeline is enabled.</returns>
    /// <exception cref="ArgumentNullException">If 'metadataAddress' is null or empty.</exception>
    /// <exception cref="ArgumentNullException">If 'configRetriever' is null.</exception>
    /// <exception cref="ArgumentNullException">If 'docRetriever' is null.</exception>
    /// <exception cref="ArgumentNullException">If 'lkgCacheOptions' is null.</exception>
    public static ConfigurationManager<T> CreateSync(string metadataAddress, IConfigurationRetrieverSync<T> configRetriever, IDocumentRetrieverSync docRetriever, LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
    {
        return new ConfigurationManager<T>(metadataAddress, configRetriever, docRetriever, lkgCacheOptions);
    }

    /// <summary>
    /// Creates a <see cref="ConfigurationManager{T}"/> backed by the synchronous retrieval contracts with a configuration validator.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetrieverSync{T}"/>.</param>
    /// <param name="docRetriever">The <see cref="IDocumentRetrieverSync"/> that reaches out to obtain the configuration.</param>
    /// <param name="configValidator">The <see cref="IConfigurationValidator{T}"/>.</param>
    /// <returns>A <see cref="ConfigurationManager{T}"/> whose synchronous pipeline is enabled.</returns>
    /// <exception cref="ArgumentNullException">If 'configValidator' is null.</exception>
    public static ConfigurationManager<T> CreateSync(string metadataAddress, IConfigurationRetrieverSync<T> configRetriever, IDocumentRetrieverSync docRetriever, IConfigurationValidator<T> configValidator)
    {
        return new ConfigurationManager<T>(metadataAddress, configRetriever, docRetriever, configValidator, new LastKnownGoodConfigurationCacheOptions());
    }

    /// <summary>
    /// Creates a <see cref="ConfigurationManager{T}"/> backed by the synchronous retrieval contracts with a configuration validator.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetrieverSync{T}"/>.</param>
    /// <param name="docRetriever">The <see cref="IDocumentRetrieverSync"/> that reaches out to obtain the configuration.</param>
    /// <param name="configValidator">The <see cref="IConfigurationValidator{T}"/>.</param>
    /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/>.</param>
    /// <returns>A <see cref="ConfigurationManager{T}"/> whose synchronous pipeline is enabled.</returns>
    /// <exception cref="ArgumentNullException">If 'configValidator' is null.</exception>
    public static ConfigurationManager<T> CreateSync(string metadataAddress, IConfigurationRetrieverSync<T> configRetriever, IDocumentRetrieverSync docRetriever, IConfigurationValidator<T> configValidator, LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
    {
        return new ConfigurationManager<T>(metadataAddress, configRetriever, docRetriever, configValidator, lkgCacheOptions);
    }

    /// <summary>
    /// Creates a <see cref="ConfigurationManager{T}"/> backed by the synchronous retrieval contracts with a configuration validator and event handler.
    /// </summary>
    /// <param name="metadataAddress">The address to obtain configuration.</param>
    /// <param name="configRetriever">The <see cref="IConfigurationRetrieverSync{T}"/>.</param>
    /// <param name="docRetriever">The <see cref="IDocumentRetrieverSync"/> that reaches out to obtain the configuration.</param>
    /// <param name="configValidator">The <see cref="IConfigurationValidator{T}"/>.</param>
    /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/>.</param>
    /// <param name="configurationEventHandler">The <see cref="IConfigurationEventHandlerSync{T}"/> that handles configuration events.</param>
    /// <returns>A <see cref="ConfigurationManager{T}"/> whose synchronous pipeline is enabled.</returns>
    /// <exception cref="ArgumentNullException">If 'configValidator' is null.</exception>
    /// <exception cref="ArgumentNullException">If 'configurationEventHandler' is null.</exception>
    public static ConfigurationManager<T> CreateSync(string metadataAddress, IConfigurationRetrieverSync<T> configRetriever, IDocumentRetrieverSync docRetriever, IConfigurationValidator<T> configValidator, LastKnownGoodConfigurationCacheOptions lkgCacheOptions, IConfigurationEventHandlerSync<T> configurationEventHandler)
    {
        if (configurationEventHandler == null)
            throw LogHelper.LogArgumentNullException(nameof(configurationEventHandler));

        ConfigurationManager<T> configurationManager = new ConfigurationManager<T>(metadataAddress, configRetriever, docRetriever, configValidator, lkgCacheOptions);
        configurationManager.ConfigurationEventHandlerSync = configurationEventHandler;

        return configurationManager;
    }
}
