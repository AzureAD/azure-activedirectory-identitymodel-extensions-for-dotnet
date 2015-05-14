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

using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace System.IdentityModel.Test
{
    public static class Issuers
    {
        public const string GotJwt = @"http://www.GotJwt.com";
        public const string GotJwtOriginal = @"http://www.GotJwt.com/Original";
        public const string Actor = @"http://www.issuer.com";
        public const string ActorOriginal = @"http://www.issuer.com/Original";
    }

    public static class Audiences
    {
        public const string AuthFactors = @"http://www.AuthFactors.com";
        public const string Empty = "";
    }

    public static class EncodedJwts
    {
        public static string Asymmetric_LocalSts =  @"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOi8vR290Snd0LmNvbSIsImF1ZCI6Imh0dHA6Ly9Db250b3NvLmNvbSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2NvdW50cnkiOiJVU0EiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiOiJ1c2VyQGNvbnRvc28uY29tIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZ2l2ZW5uYW1lIjoiVG9ueSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2hvbWVwaG9uZSI6IjU1NS4xMjEyIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiU2FsZXMiLCJzdWIiOiJib2IifQ.QW0Wfw-R5n3BHXE0vG-0giRFeB6W9oFrWJyFTaLI0qICDYx3yZ2eLXJ3zNFLVf3OG-MqytN5tqUdNfK1mRzeubqvdODHLFX36e1o3X8DR_YumyyQvgSeTJ0wwqT8PowbE3nbKfiX4TtJ4jffBelGKnL6vdx3AU2cwvLfSVp8ppA";
        public static string Asymmetric_1024 =      @"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOi8vR290Snd0LmNvbSIsImF1ZCI6Imh0dHA6Ly9Db250b3NvLmNvbSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2NvdW50cnkiOiJVU0EiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiOiJ1c2VyQGNvbnRvc28uY29tIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZ2l2ZW5uYW1lIjoiVG9ueSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2hvbWVwaG9uZSI6IjU1NS4xMjEyIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiU2FsZXMiLCJzdWIiOiJib2IifQ.WlNiBiAqmS4G-Em5O-uYiWLK5CJO8B-6Hvqjv_DXpoxldGiMWzivuyJocXPIIDVbcLxovmTc5j0KKgA9foOFBSkEEasqESA0VTYE30T1kkrGOaElola5DZagzax2zDipjxhbtBdMsvgF2t6GQJKyF0oFt828_yRGUsUnaXxg_MY";
        public static string Asymmetric_2048 =      @"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOi8vR290Snd0LmNvbSIsImF1ZCI6Imh0dHA6Ly9Db250b3NvLmNvbSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2NvdW50cnkiOiJVU0EiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiOiJ1c2VyQGNvbnRvc28uY29tIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZ2l2ZW5uYW1lIjoiVG9ueSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2hvbWVwaG9uZSI6IjU1NS4xMjEyIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiU2FsZXMiLCJzdWIiOiJib2IifQ.XYeDHk0XRs1ybrk2AMWu3ZwNC6gPUYqxacJtUDSfQCGouRFdmkYtZcgvWAhH8iFv3DmPgfX0lI9WCtjN2JOZqOx5w90r9UKCh_9e_vUKZyjLkyUEv3iBl2HTpxfcj3ns5MmZI50N8O2cYq1d6-CRK_oi8oKhLWKfrD8LoMpCtV8zjraEB1GUfJvMrxPTIzHSF-V_nmu5aPIoHVyxAcc1jShkYdnS5Dz8nVqLBleCAQ2Tv-8N9Q8l1362b088y15auc-hBb76KmMU2aCutyJDRz0NqsCkFz-cV-vnIj-hzl562DzSUP48nEMTwEIO_bRKex1R5beZ36ZrKLP1GQxc8Q";
        public static string Symmetric_256   =      @"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vR290Snd0LmNvbSIsImF1ZCI6Imh0dHA6Ly9Db250b3NvLmNvbSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2NvdW50cnkiOiJVU0EiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiOiJ1c2VyQGNvbnRvc28uY29tIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZ2l2ZW5uYW1lIjoiVG9ueSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2hvbWVwaG9uZSI6IjU1NS4xMjEyIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiU2FsZXMiLCJzdWIiOiJib2IifQ._IFPA82MzKeV4IrsgZX8mkAEfzWT8-zEE4b5R2nzih4";
        public static string InvalidPayload =       @"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dCI6InZ4VThJR1pYdEFtemg0NzdDT05CR2dYRTlfYyJ9.eyJcdWQiOiJodHRwOi8vbG9jYWxob3N0L1JQIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdC9TdHMiLCJuYmYiOjEzNjcyODA0MDUsImV4cCI6MTM2NzMwOTIwNSwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZ2l2ZW5uYW1lIjoiYWFsIn0.Pro66IUD94jvZNnG_l96Hph78L_LYSx6eobO6QfWF3y038ebLZorhKYgAj1LtsNVAbq7E_I5tnoI1Y4YUV5_wMGtMqT_XTB4N8vktDzf0Y32MhopsDrveofJAAFAUP1npYZtFF89RAWzy1GaXqXw05SbUcyMPWTSvmPk_frzJRTc-utAaBAp-zKqS1KXGB_s99x7lDxy3ZFMDFtFHQlOJiXeClXYCVkB-ZmvrSFSAIasFK4eIG9pOcMY43_wS7ybNjF7WncY6PEi6JmUoh2AwA-SCdY-Bhs80Tf4GMB2HsmuMkSVgoptt6Fgf-q8LhWG0W80g66JRgdhMj85BZ6bxg";
        public static string LiveJwt        =       @"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAiLCJ0eXAiOiJKV1QifQ.eyJ2ZXIiOjEsImlzcyI6InVybjp3aW5kb3dzOmxpdmVpZCIsImV4cCI6MTM2ODY0ODg2MywidWlkIjoiMzgwZTE3YzMxNGU2ZmMyODA0NzA3MjI5NTc3MjEwZmIiLCJhdWQiOiJ3d3cuc3JpLWRldjEwMC5jb20iLCJ1cm46bWljcm9zb2Z0OmFwcHVyaSI6Im1zLWFwcDovL1MtMS0xNS0yLTM2MzczOTQzNzAtMjIzMTgyMTkzNi01NjUwMTU1MS0xNTE0NjEzNDgyLTQ1NjgzNjc4LTM1NzUyNjE4NTItMjMzNTgyNjkwIiwidXJuOm1pY3Jvc29mdDphcHBpZCI6IjAwMDAwMDAwNEMwRTdBNUMifQ.I-sE7t6IJUho1TfgaLilNuzro-pWOMgg33rQ351GcoM";
        public static string OverClaims =           @"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImtyaU1QZG1Cdng2OHNrVDgtbVBBQjNCc2VlQSJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLndpbmRvd3MubmV0IiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3LyIsImlhdCI6MTQwNTk2ODkyMiwibmJmIjoxNDA1OTY4OTIyLCJleHAiOjE0MDU5NzI4MjIsInZlciI6IjEuMCIsInRpZCI6IjcyZjk4OGJmLTg2ZjEtNDFhZi05MWFiLTJkN2NkMDExZGI0NyIsImFtciI6WyJwd2QiXSwib2lkIjoiMzVjNzZlZWQtZjY0MC00YWU3LWFhZTItMzI3NzE3MWVhM2U1IiwidXBuIjoibmJhbGlnYUBtaWNyb3NvZnQuY29tIiwidW5pcXVlX25hbWUiOiJuYmFsaWdhQG1pY3Jvc29mdC5jb20iLCJzdWIiOiI1R0UwVkhBSlBuaUdNSWluN3dMNFBFMFE5MjAzTG00bHJBUnBrcEFBYmprIiwicHVpZCI6IjEwMDM3RkZFODAxQjI4QTAiLCJmYW1pbHlfbmFtZSI6IkJhbGlnYSIsImdpdmVuX25hbWUiOiJOYW1yYXRhIiwiX2NsYWltX25hbWVzIjp7Imdyb3VwcyI6InNyYzEifSwiX2NsYWltX3NvdXJjZXMiOnsic3JjMSI6eyJlbmRwb2ludCI6Imh0dHBzOi8vZ3JhcGgud2luZG93cy5uZXQvNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3VzZXJzLzM1Yzc2ZWVkLWY2NDAtNGFlNy1hYWUyLTMyNzcxNzFlYTNlNS9nZXRNZW1iZXJPYmplY3RzIn19LCJhcHBpZCI6IjExOGUxNzBmLWNmMjYtNDAwZi1hMGU5LTk2OTEwYjMxMTg3ZSIsImFwcGlkYWNyIjoiMSIsInNjcCI6IlVzZXJQcm9maWxlLlJlYWQiLCJhY3IiOiIxIn0.PWNfaBajC6KAr2dKiG0aJ1295hIXm9XWZPdrCw6zMgT0s46rrcBFMWOJQ-4Cz1aSqour6tslg8cl4_1rAjlkVwsXs7QTekMHxIcf3SPpM6vPTa7OfQ4dzBbPQV_QKif1xBXDkFQfZPAF2tPwcK_VBzHT0Z94_CpOtxChXmGEctW38Rt6f8bC_aaD6nsTZOt6NdAmI2AVOchpp7qNWEdBTvdcoNyz_a5VbUwWsHGCvozcOLjjFLles-K0BhiFw3MyJU_DMG-H6TgeBtwJPiuU2vHUTea26sfKHbpe7GypBo1PjY7odDWMH-d7c1Z0fT-UL15dAV419zX1NGbl-cujsw";
        public static string Cyrano = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImtyaU1QZG1Cdng2OHNrVDgtbVBBQjNCc2VlQSJ9.eyJhdWQiOiJmZTc4ZTBiNC02ZmU3LTQ3ZTYtODEyYy1mYjc1Y2VlMjY2YTQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9hZGQyOTQ4OS03MjY5LTQxZjQtODg0MS1iNjNjOTU1NjQ0MjAvIiwiaWF0IjoxNDE5MjY4NTIwLCJuYmYiOjE0MTkyNjg1MjAsImV4cCI6MTQxOTI3MjQyMCwidmVyIjoiMS4wIiwidGlkIjoiYWRkMjk0ODktNzI2OS00MWY0LTg4NDEtYjYzYzk1NTY0NDIwIiwiYW1yIjpbInB3ZCJdLCJvaWQiOiI4MDAyNzk2NC1jZDcwLTRmMmMtOTcwMC0yYzFhNmRiNTZlZjYiLCJ1cG4iOiJib2JAY3lyYW5vLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoiYm9iQGN5cmFuby5vbm1pY3Jvc29mdC5jb20iLCJzdWIiOiJoMnh6WVczbWdUWmZad3B3T1d4QTFZcDJ0am9Xc0ZxOWlGa1AxTjJRUndrIiwiZmFtaWx5X25hbWUiOiJDeXJhbm8iLCJnaXZlbl9uYW1lIjoiQm9iIiwibm9uY2UiOiI2MzU1NDg2NTYxMzk1MzcwNDYuT0RZMU5EWTRaRGt0T1RNNE55MDBaR0l5TFRnMk1EQXRZakkxTWpNME9HVXhOVGRtTkRVek5USXlNR0V0WldJd1lTMDBNMkpoTFRobE4yUXRaVFEwWWpJMk1tRTFaak16IiwiY19oYXNoIjoiMXVHNEVfWWdYcTZkVUctTExzeGtjQSIsInB3ZF9leHAiOiI1MzQ1MDIiLCJwd2RfdXJsIjoiaHR0cHM6Ly9wb3J0YWwubWljcm9zb2Z0b25saW5lLmNvbS9DaGFuZ2VQYXNzd29yZC5hc3B4In0.juYFCrJbDPwqZeNmR9XiFRh3iobf76fKHrE4ViqELbuz0cHhAWzntR_kshoyCCBx5Q_uQcAYnrUyvHuXsQoLqUHot6Ksnlc7uUFAeWBgSIAIRX2np-fCn0_CzgwgvBu9KOUV27uu28tEPBfxHCmU9CCH41aSLoGzGBiorQ_ss0LO3ZapLiB5T2yRaJh-ZCSuGbjTCvMAmUFx4I2rvHSNaJQOqUT02EjkHzU3qAJuYSH1Z_G36Bfyiixpbyq8Txewqaot0sHCwOrBY9yjTx8Ijrnbn7_xQHV2LyvUnSxZjL0bVUZRmWyXJ0st7Cjd9intcMYb60XSmkZwLfKzMtBY2Q";
    }

    public static class Saml2SignedTokens
    {
        public static readonly string AAD_GotJWT = @"<Assertion ID='_775bef7d-0ba5-4df5-98f8-ec57f2b0cbef' IssueInstant='2013-04-11T20:02:45.903Z' Version='2.0' xmlns='urn:oasis:names:tc:SAML:2.0:assertion'><Issuer>https://sts.windows.net/d062b2b0-9aca-4ff7-b32a-ba47231a4002/</Issuer><ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><ds:SignedInfo><ds:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /><ds:SignatureMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' /><ds:Reference URI='#_775bef7d-0ba5-4df5-98f8-ec57f2b0cbef'><ds:Transforms><ds:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature' /><ds:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /></ds:Transforms><ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256' /><ds:DigestValue>m1jXR5LORy7H+t+axtNauGnJakaKehvy0JhMZomZFrU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>IhaRBWAG/QeskVPO5Qa3EGN0A/bJ8qPqmJnuhox5F3aAGgqeoxbMhdwDMuQ7GC/7ScYDtYnAKATV6xP0nKTzwlqj1ltDEDN9scDuJIotwnV+xm4PCqlIeSZBHfyhIDp0rlhZDmhOnNy6+53FqVWMo7aSE1FdMCEh2aBgTRLH4jBkx5pKV0kQOX9D0Hq2GaV0LaXjcguADKxPpb1Gl+g8g/H/79n96fHAPITA8WygZjv1Satow87N8WK49n9qZJBWqmMjaVix6oFHPMOkp/qWE7ZhWKS1ANU2AwLMvZ8AH+RDwhWTWHnLCq2duD4XlCTRiY8juIn+zgJ51sfWQRYa2w==</ds:SignatureValue><KeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#'><X509Data><X509Certificate>MIIDPjCCAiqgAwIBAgIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTIwNjA3MDcwMDAwWhcNMTQwNjA3MDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVwIDAQABo2IwYDBeBgNVHQEEVzBVgBCxDDsLd8xkfOLKm4Q/SzjtoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAA4IBAQAkJtxxm/ErgySlNk69+1odTMP8Oy6L0H17z7XGG3w4TqvTUSWaxD4hSFJ0e7mHLQLQD7oV/erACXwSZn2pMoZ89MBDjOMQA+e6QzGB7jmSzPTNmQgMLA8fWCfqPrz6zgH+1F1gNp8hJY57kfeVPBiyjuBmlTEBsBlzolY9dd/55qqfQk6cgSeCbHCy/RU/iep0+UsRMlSgPNNmqhj5gmN2AFVCN96zF694LwuPae5CeR2ZcVknexOWHYjFM0MgUSw0ubnGl0h9AJgGyhvNGcjQqu9vd1xkupFgaN+f7P3p3EVN5csBg5H94jEcQZT7EKeTiZ6bTrpDAnrr8tDCy8ng</X509Certificate></X509Data></KeyInfo></ds:Signature><Subject><NameID>X3hlFkILohbCj9c2Iib1NJg7e3hGhVsJdHuA7WRABp4</NameID><SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer' /></Subject><Conditions NotBefore='2013-04-11T20:02:45.840Z' NotOnOrAfter='2013-04-12T08:02:45.840Z'><AudienceRestriction><Audience>https://localhost:44300/</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name='http://schemas.microsoft.com/identity/claims/objectidentifier'><AttributeValue>580e531c-87a4-415a-9f9d-6af51e2e1948</AttributeValue></Attribute><Attribute Name='http://schemas.microsoft.com/identity/claims/tenantid'><AttributeValue>d062b2b0-9aca-4ff7-b32a-ba47231a4002</AttributeValue></Attribute><Attribute Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'><AttributeValue>Got</AttributeValue></Attribute><Attribute Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'><AttributeValue>GotJwt@GotJwt.onmicrosoft.com</AttributeValue></Attribute><Attribute Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'><AttributeValue>Jwt</AttributeValue></Attribute><Attribute Name='http://schemas.microsoft.com/identity/claims/identityprovider'><AttributeValue>https://sts.windows.net/d062b2b0-9aca-4ff7-b32a-ba47231a4002/</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant='2013-04-11T20:02:45.000Z'><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>";
    }

    public static class JsonClaims
    {
        public static readonly string GroupClaims = @"{""iss"":[""http://www.GotJWT.com"",""https://sts.windows.net/5803816d-c4ab-4601-a128-e2576e5d6910/""],""aud"":[""http://www.contoso.com"",""0bb44690-eae0-4b2c-b2b1-64ac03098226""],""upn"":""badams@dushyantgill.net"",""family_name"":""Adams"",""unique_name"":""badams@dushyantgill.net"",""ver"":""1.0"",""groups"":[""c4324023-3424-4ba6-9320-1ce28431b113"",""08953f81-ffd6-44f9-887d-69855355ffbd"",""694a55b2-ec4c-480d-8a7d-26d34ea9225b""],""oid"":""0c9545d0-a670-4628-8c1f-e90618a3b940"",""nonce"":""02f9c7ba-1720-4d46-b00f-6731fe2c4d14"",""given_name"":""Brad"",""exp"":1405870465,""tid"":""5803816d-c4ab-4601-a128-e2576e5d6910"",""iat"":""1403822988"",""amr"":""pwd"",""nbf"":1405866865,""sub"":""355anlmMo6uvGyabeIqNqBTUJsEPdyijxouLjfmg8G8""}";

        public static Dictionary<string, Dictionary<string, string>> ClaimSources
        {
            get
            {
                return new Dictionary<string, Dictionary<string, string>>
                {
                    {   "src1",
                        new Dictionary<string,string>
                        {
                            { "endpoint", "https://graph.windows.net/5803816d-c4ab-4601-a128-e2576e5d6910/users/0c9545d0-a670-4628-8c1f-e90618a3b940/getMemberObjects"},
                            { "access_token", "ksj3n283dke"}
                        }
                    },
                    {   "src2",
                        new Dictionary<string,string>
                        {
                            { "endpoint2", "https://graph.windows.net/5803816d-c4ab-4601-a128-e2576e5d6910/users/0c9545d0-a670-4628-8c1f-e90618a3b940/getMemberObjects"},
                            { "access_token2", "ksj3n283dke"}
                        }
                    }

                };
            }
        }

        public static Dictionary<string, string> ClaimNames
        {
            get
            {
                return new Dictionary<string, string>
                {
                    { "groups",
                      "src1"
                    },
                    { "groups2",
                      "src2"
                    }
                };
            }
        }

        public static ClaimsIdentity ClaimsIdentityDistributedClaims(string issuer, string authType, Dictionary<string, Dictionary<string, string>> claimSources, Dictionary<string, string> claimNames )
        {
            List<Claim> claims = new List<Claim>();
            // TODO - workaround for null ref in Claim.Clone(). Was fixed and checked in 2/19, still hasn't made it to a build.
            ClaimsIdentity claimsIdentity = new ClaimsIdentity(authType);
            AddClaimSources(claimSources, claims, issuer, claimsIdentity);
            AddClaimNames(claimNames, claims, issuer, claimsIdentity);
            claimsIdentity.AddClaims(claims);
            return claimsIdentity;
        }

        public static void AddClaimNames(Dictionary<string, string> claimNames, List<Claim> claims, string issuer, ClaimsIdentity subject)
        {
            foreach(var kv in claimNames)
            {
                Claim c = new Claim("_claim_names", @"""" + kv.Key + @""":""" + kv.Value + @"""", JwtConstants.JsonClaimValueType, issuer, issuer, subject);
                c.Properties[JwtSecurityTokenHandler.JsonClaimTypeProperty] = "Newtonsoft.Json.Linq.JProperty";
                claims.Add(c);
            }
        }

        public static void AddClaimSources(Dictionary<string, Dictionary<string, string>> claimSources, List<Claim> claims, string issuer, ClaimsIdentity subject)
        {
            foreach (var kv in claimSources)
            {
                Claim c = new Claim("_claim_sources", @"""" + kv.Key + @""":" + JsonExtensions.SerializeToJson(kv.Value), JwtConstants.JsonClaimValueType, issuer, issuer, subject);
                c.Properties[JwtSecurityTokenHandler.JsonClaimTypeProperty] = "Newtonsoft.Json.Linq.JProperty";
                claims.Add(c);
            }
        }
    }
}