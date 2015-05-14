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

using Microsoft.IdentityModel.Protocols;
using System;

namespace Microsoft.IdentityModel.Test
{
    public class MessageComparer
    {
        public static bool AreEqual(AuthenticationProtocolMessage authenticationProtocolMessage1, AuthenticationProtocolMessage authenticationProtocolMessage2)
        {
            if (!DoObjectsHaveSameNullState(authenticationProtocolMessage1, authenticationProtocolMessage2))
            {
                return false;
            }

            if (authenticationProtocolMessage1 == null)
            {
                return true;
            }

            if (!DoObjectsHaveSameNullState(authenticationProtocolMessage1.IssuerAddress, authenticationProtocolMessage2.IssuerAddress))
            {
                return false;
            }

            if (authenticationProtocolMessage1.IssuerAddress != null && authenticationProtocolMessage1.IssuerAddress != authenticationProtocolMessage2.IssuerAddress)
            {
                return false;
            }

            if (authenticationProtocolMessage1.Parameters.Count != authenticationProtocolMessage2.Parameters.Count)
            {
                return false;
            }

            return true;
        }

#if SAML
        public static bool AreEqual(WsFederationMessage wsFederationMessage1, WsFederationMessage wsFederationMessage2)
        {
            if (!MessageComparer.AreEqual(wsFederationMessage1 as AuthenticationProtocolMessage, wsFederationMessage2 as AuthenticationProtocolMessage))
            {
                return false;
            }

            return true;
        }
#endif
        static bool DoObjectsHaveSameNullState(object object1, object object2)
        {
            if ((object1 == null && object2 != null) || (object1 != null && object2 == null))
            {
                return false;
            }

            return true;
        }
    }
}