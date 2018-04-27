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

using AsyncCommon;
using Microsoft.IdentityModel.S2S.Tokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Jwt;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace AsyncWebsite.Controllers
{
    public class HomeController : Controller
    {
        private JsonWebTokenHandler _tokenHandler = new JsonWebTokenHandler();

        // AsyncWebsite metadata
        public const string Address = "http://localhost:48272/";

        // AsyncWebAPI metadata
        public const string MiddleTierAddress = "http://localhost:48273/";
        public const string MiddleTierEndpoint = MiddleTierAddress + "api/AccessTokenProtected/ProtectedApi";

        public ActionResult Index()
        {
            ViewBag.Error = string.Empty;
            ViewBag.Response = "Token verification response has not been recieved yet.";
            ViewBag.Title = "AsyncWebsite";
            ViewData["Name"] = "AsyncWebsite";

            return View();
        }

        public async Task<ViewResult> SendToken()
        {
            var signingCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials;
            signingCredentials.CryptoProviderFactory = new CryptoProviderFactory()
            {
                CustomCryptoProvider = new AsyncCryptoProvider(KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key, KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Algorithm, true)
            };

            var payload = new JObject()
            {
                { JwtRegisteredClaimNames.Email, "Bob@contoso.com"},
                { JwtRegisteredClaimNames.GivenName, "Bob"},
                { JwtRegisteredClaimNames.Iss, "http://Default.Issuer.com" },
                { JwtRegisteredClaimNames.Aud, "http://Default.Audience.com" },
                { JwtRegisteredClaimNames.Nbf, "2017-03-18T18:33:37.080Z" },
                { JwtRegisteredClaimNames.Exp, "2021-03-17T18:33:37.080Z" }
            };

            var accessToken = await _tokenHandler.CreateJWSAsync(payload, signingCredentials).ConfigureAwait(false);
            ViewBag.Error = string.Empty;
            ViewBag.Response = "Token verification response has not been recieved yet.";
            ViewBag.Title = "AsyncWebsite";
            try
            {
                var httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Add(AuthenticationConstants.AuthorizationHeader, AuthenticationConstants.BearerWithSpace + accessToken);
                var httpResponse = await httpClient.GetAsync(MiddleTierEndpoint).ConfigureAwait(false);

                ViewBag.Response = await httpResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.ToString();
            }

            ViewData["Name"] = "AsyncWebsite";

            return View("Index");
        }
    }
}
