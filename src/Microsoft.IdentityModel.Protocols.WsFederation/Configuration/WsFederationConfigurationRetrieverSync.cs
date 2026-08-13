// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.IO;
using System.Threading;
using System.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Protocols.WsFederation;

internal sealed class WsFederationConfigurationRetrieverSync : IConfigurationRetrieverSync<WsFederationConfiguration>
{
    private static readonly XmlReaderSettings SafeSettings = new XmlReaderSettings
    {
        XmlResolver = null,
        DtdProcessing = DtdProcessing.Prohibit,
        ValidationType = ValidationType.None
    };

    public WsFederationConfiguration GetConfigurationSync(string address, IDocumentRetrieverSync retriever, CancellationToken cancel)
    {
        if (string.IsNullOrEmpty(address))
            throw LogArgumentNullException(nameof(address));

        if (retriever == null)
            throw LogArgumentNullException(nameof(retriever));

        string document = retriever.GetDocument(address, cancel);

        using var metadataReader = XmlReader.Create(new StringReader(document), SafeSettings);
        return new WsFederationMetadataSerializer().ReadMetadata(metadataReader);
    }
}
