// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using Microsoft.IdentityModel.Tokens.Configuration;

namespace Microsoft.IdentityModel.Tokens;

internal abstract class BaseConfigurationManagerSync : BaseConfigurationManager
{
    protected BaseConfigurationManagerSync()
    {
    }

    protected BaseConfigurationManagerSync(LKGConfigurationCacheOptions options)
        : base(options)
    {
    }

    internal abstract BaseConfiguration GetBaseConfigurationSync(CancellationToken cancellationToken);
}
