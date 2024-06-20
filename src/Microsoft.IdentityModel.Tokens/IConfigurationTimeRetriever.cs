// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// 
    /// </summary>
    // L2 TODO: internal until L2 cache is implemented S2S.
    internal interface IConfigurationTimeRetriever
    {
        // L2 TODO: internal until L2 cache is implemented S2S.
        internal DateTimeOffset RetrievalTime { get; set; }
    }
}
