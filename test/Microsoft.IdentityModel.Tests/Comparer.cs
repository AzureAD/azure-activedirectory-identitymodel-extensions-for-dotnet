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
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Xml;
using static Microsoft.IdentityModel.Tests.IdentityComparer;

namespace Microsoft.IdentityModel.Tests
{
    public static class Comparer
    {
        public static void GetDiffs(KeyInfo keyInfo1, KeyInfo keyInfo2, List<string> diffs)
        {
            var context = new CompareContext();
            if (ContinueCheckingEquality(keyInfo1, keyInfo2, context))
                CompareAllPublicProperties(keyInfo1, keyInfo2, context);

            diffs.AddRange(context.Diffs);
        }

        public static void GetDiffs(IList<KeyInfo> keyInfos1, IList<KeyInfo> keyInfos2, List<string> diffs)
        {
            var context = new CompareContext();
            if (ContinueCheckingEquality(keyInfos1, keyInfos2, context))
            {
                if (keyInfos1.Count == keyInfos2.Count)
                {
                    for (int i = 0; i<keyInfos1.Count; i++)
                    {
                        GetDiffs(keyInfos1[i], keyInfos2[i], diffs);
                    }
                }
                else
                {
                    diffs.Add($"keyInfos1.Count != keyInfos2.Count, '{keyInfos1.Count} : {keyInfos2.Count}");
                    return;
                }
            }

            diffs.AddRange(context.Diffs);
        }

        public static void GetDiffs(OpenIdConnectMessage message1, OpenIdConnectMessage message2, List<string> diffs)
        {
            var context = new CompareContext();
            if (ContinueCheckingEquality(message1, message2, context))
                CompareAllPublicProperties(message1, message2, context);

            diffs.AddRange(context.Diffs);
        }

        public static void GetDiffs(Reference reference1, Reference reference2, List<string> diffs)
        {
            var context = new CompareContext();
            if (ContinueCheckingEquality(reference1, reference2, context))
                CompareAllPublicProperties(reference1, reference2, context);

            diffs.AddRange(context.Diffs);

            if (ContinueCheckingEquality(reference1.TransformChain, reference2.TransformChain, context))
                CompareAllPublicProperties(reference1.TransformChain, reference2.TransformChain, context);

            if (reference1.TransformChain.Count != reference2.TransformChain.Count)
                diffs.Add($" Reference.TransformChain.TransformCount: {reference1.TransformChain.Count}, {reference2.TransformChain.Count}");
            else if (reference1.TransformChain.Count > 0)
            {
                for (int i = 0; i < reference1.TransformChain.Count; i++)
                {
                    if (reference1.TransformChain[i].GetType() != reference2.TransformChain[i].GetType())
                        diffs.Add($" Reference.TransformChain[{i}].GetType(): {reference1.TransformChain[i].GetType()} : {reference2.TransformChain[i].GetType()}");
                }
            }
        }

        public static void GetDiffs(Signature signature1, Signature signature2, List<string> diffs)
        {
            var context = new CompareContext();
            if (ContinueCheckingEquality(signature1, signature2, context))
                CompareAllPublicProperties(signature1, signature2, context);

            diffs.AddRange(context.Diffs);
        }

        public static void GetDiffs(SignedInfo signedInfo1, SignedInfo signedInfo2, List<string> diffs)
        {
            var context = new CompareContext();
            if (ContinueCheckingEquality(signedInfo1, signedInfo2, context))
                CompareAllPublicProperties(signedInfo1, signedInfo2, context);

            diffs.AddRange(context.Diffs);
        }

        public static void GetDiffs(WsFederationConfiguration configuration1, WsFederationConfiguration configuration2, List<string> diffs)
        {
            var context = new CompareContext();
            if (ContinueCheckingEquality(configuration1, configuration2, context))
                CompareAllPublicProperties(configuration1, configuration2, context);

            diffs.AddRange(context.Diffs);
        }

        public static void GetDiffs(WsFederationMessage message1, WsFederationMessage message2, List<string> diffs)
        {
            var context = new CompareContext();
            if (ContinueCheckingEquality(message1, message2, context))
                CompareAllPublicProperties(message1, message2, context);

            diffs.AddRange(context.Diffs);

            if (message1.Parameters.Count != message2.Parameters.Count)
                diffs.Add($" message1.Parameters.Count != message2.Parameters.Count: {message1.Parameters.Count}, {message2.Parameters.Count}");

            var stringComparer = StringComparer.Ordinal;
            foreach (var param in message1.Parameters)
            {
                if (!message2.Parameters.TryGetValue(param.Key, out string value2))
                    diffs.Add($" WsFederationMessage.message1.Parameters.param.Key missing in message2: {param.Key}");
                else if (param.Value != value2)
                    diffs.Add($" WsFederationMessage.message1.Parameters.param.Value !=  message2.Parameters.param.Value: {param.Key}, {param.Value}, {value2}");
            }

            foreach (var param in message2.Parameters)
            {
                if (!message1.Parameters.TryGetValue(param.Key, out string value1))
                    diffs.Add($" WsFederationMessage.message2.Parameters.param.Key missing in message1: {param.Key}");
                else if (param.Value != value1)
                    diffs.Add($" WsFederationMessage.message2.Parameters.param.Value !=  message1.Parameters.param.Value: {param.Key}, {param.Value}, {value1}");
            }
        }
    }
}
