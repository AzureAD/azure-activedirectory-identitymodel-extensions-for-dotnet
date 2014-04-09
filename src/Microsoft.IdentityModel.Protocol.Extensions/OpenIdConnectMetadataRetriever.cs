// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Net.Http;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography.X509Certificates;
using System.Web.Script.Serialization;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Helper for parsing OpenidConnect metadata.
    /// </summary>
    public static class OpenIdConnectMetadataRetriever
    {
        /// <summary>
        /// Obtains <see cref="OpenIdConnectMetadata"/> from an endpoint.
        /// </summary>
        /// <param name="metadataEndpoint"> the endpoint to query.</param>
        /// <param name="httpClient">the <see cref="HttpClient"/> to use to make the call.</param>
        /// <returns></returns>
        public static OpenIdConnectMetadata GetMetatadata(string metadataEndpoint, HttpClient httpClient)
        {
            if (metadataEndpoint == null)
            {
                throw new ArgumentNullException("metadataEndpoint");
            }

            if (httpClient == null)
            {
                throw new ArgumentNullException("httpClient");
            }

            HttpResponseMessage metadataResponse = httpClient.GetAsync(metadataEndpoint).Result;
            metadataResponse.EnsureSuccessStatusCode();
            Stream stream = metadataResponse.Content.ReadAsStreamAsync().Result;
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(OpenIdConnectMetadata));
            OpenIdConnectMetadata openIdConnectMetadata = serializer.ReadObject(stream) as OpenIdConnectMetadata;
            
            if (!string.IsNullOrEmpty(openIdConnectMetadata.Jwks_Uri))
            {
                metadataResponse = httpClient.GetAsync(openIdConnectMetadata.Jwks_Uri).Result;
                metadataResponse.EnsureSuccessStatusCode();
                string str = metadataResponse.Content.ReadAsStringAsync().Result;
                JavaScriptSerializer jss = new JavaScriptSerializer();
                Dictionary<string, object> jsonKey = jss.Deserialize<Dictionary<string, object>>(str);
                object obj = null;
                if (jsonKey.TryGetValue(JsonWebKeysValueNames.Keys, out obj ))
                {
                    var collection = obj as ArrayList;
                    if (collection != null)
                    {
                        foreach(object entry in collection)
                        {
                            Dictionary<string, object> objectEntry = entry as Dictionary<string, object>;
                            if (objectEntry.ContainsKey(JsonWebKeysValueNames.X5c))
                            {
                                var x509DataCollection = objectEntry[JsonWebKeysValueNames.X5c] as ArrayList;
                                if (x509DataCollection != null)
                                {
                                    foreach (object x509DataObject in x509DataCollection)
                                    {
                                        string x509Data = x509DataObject as string;
                                        if (x509Data != null)
                                        {
                                            X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(x509Data));
                                            openIdConnectMetadata.SigningTokens.Add(new X509SecurityToken(cert));
                                        }
                                    }                                
                                }
                            }
                        }
                    }
                }
            }

            return openIdConnectMetadata;
        }
    }
}
