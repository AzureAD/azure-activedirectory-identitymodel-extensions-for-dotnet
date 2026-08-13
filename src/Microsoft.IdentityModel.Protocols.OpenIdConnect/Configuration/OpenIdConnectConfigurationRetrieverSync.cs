// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect;

internal sealed class OpenIdConnectConfigurationRetrieverSync : IConfigurationRetrieverSync<OpenIdConnectConfiguration>
{
    public OpenIdConnectConfiguration GetConfigurationSync(string address, IDocumentRetrieverSync retriever, CancellationToken cancel)
    {
        if (string.IsNullOrWhiteSpace(address))
            throw LogHelper.LogArgumentNullException(nameof(address));

        if (retriever == null)
            throw LogHelper.LogArgumentNullException(nameof(retriever));

        string document = retriever.GetDocument(address, cancel);

        if (LogHelper.IsEnabled(EventLogLevel.Verbose))
            LogHelper.LogVerbose(LogMessages.IDX21811, document);

        OpenIdConnectConfiguration configuration = OpenIdConnectConfigurationSerializer.Read(document);
        if (!string.IsNullOrEmpty(configuration.JwksUri))
        {
            if (LogHelper.IsEnabled(EventLogLevel.Verbose))
                LogHelper.LogVerbose(LogMessages.IDX21812, configuration.JwksUri);

            string keys = retriever.GetDocument(configuration.JwksUri, cancel);

            if (LogHelper.IsEnabled(EventLogLevel.Verbose))
                LogHelper.LogVerbose(LogMessages.IDX21813, configuration.JwksUri);

            configuration.JsonWebKeySet = new JsonWebKeySet(keys);
            foreach (SecurityKey key in configuration.JsonWebKeySet.GetSigningKeys())
                configuration.SigningKeys.Add(key);
        }

        return configuration;
    }
}
