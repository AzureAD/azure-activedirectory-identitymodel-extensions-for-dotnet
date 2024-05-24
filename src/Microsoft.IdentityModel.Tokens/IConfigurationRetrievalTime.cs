// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// 
    /// </summary>
    public interface IConfigurationRetrievalTime
    {
        /// <summary>
        /// </summary>
        public DateTimeOffset RetrievalTime { get; set; }
    }
}
