// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Text.Encodings.Web;
using System.Text.Json;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// JsonEncodedText used with utf8Writer when writing property names for JsonWebKey.
    /// Common names are initialized on startup, lazy for others.
    /// </summary>
    internal static class EncodedJsonWebKeyParameterNames
    {
        internal static bool _algSet;
        internal static JsonEncodedText _alg;
        internal static bool _crvSet;
        internal static JsonEncodedText _crv;
        internal static bool _dSet;
        internal static JsonEncodedText _d;
        internal static bool _dpSet;
        internal static JsonEncodedText _dp;
        internal static bool _dqSet;
        internal static JsonEncodedText _dq;
        internal static bool _kSet;
        internal static JsonEncodedText _k;
        internal static bool _keyopsSet;
        internal static JsonEncodedText _keyOps;
        internal static bool _othSet;
        internal static JsonEncodedText _oth;
        internal static bool _pSet;
        internal static JsonEncodedText _p;
        internal static bool _qSet;
        internal static JsonEncodedText _q;
        internal static bool _qiSet;
        internal static JsonEncodedText _qi;
        internal static bool _x5tS256Set;
        internal static JsonEncodedText _x5tS256;
        internal static bool _x5uSet;
        internal static JsonEncodedText _x5u;
        internal static bool _xSet;
        internal static JsonEncodedText _x;
        internal static bool _ySet;
        internal static JsonEncodedText _y;

        public static JsonEncodedText Alg
        {
            get
            {
                if (!_algSet)
                {
                    _alg = JsonEncodedText.Encode(JsonWebKeyParameterNames.Alg, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _algSet = true;
                }

                return _alg;
            }
        }

        public static JsonEncodedText Crv
        {
            get
            {
                if (!_crvSet)
                {
                    _crv = JsonEncodedText.Encode(JsonWebKeyParameterNames.Crv, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _crvSet = true;
                }

                return _crv;
            }
        }

        public static JsonEncodedText D
        {
            get
            {
                if (!_dSet)
                {
                    _d = JsonEncodedText.Encode(JsonWebKeyParameterNames.D, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _dSet = true;
                }

                return _d;
            }
        }

        public static JsonEncodedText DP
        {
            get
            {
                if (!_dpSet)
                {
                    _dp = JsonEncodedText.Encode(JsonWebKeyParameterNames.DP, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _dpSet = true;
                }

                return _dp;
            }
        }

        public static JsonEncodedText DQ
        {
            get
            {
                if (!_dqSet)
                {
                    _dq = JsonEncodedText.Encode(JsonWebKeyParameterNames.DQ, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _dqSet = true;
                }

                return _dq;
            }
        }

        public static readonly JsonEncodedText E = JsonEncodedText.Encode(JsonWebKeyParameterNames.E, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);

        public static JsonEncodedText K
        {
            get
            {
                if (!_kSet)
                {
                    _k = JsonEncodedText.Encode(JsonWebKeyParameterNames.K, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _kSet = true;
                }

                return _k;
            }
        }

        public static JsonEncodedText KeyOps
        {
            get
            {
                if (!_keyopsSet)
                {
                    _keyOps = JsonEncodedText.Encode(JsonWebKeyParameterNames.KeyOps, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _keyopsSet = true;
                }

                return _keyOps;
            }
        }

        public static readonly JsonEncodedText Keys = JsonEncodedText.Encode(JsonWebKeyParameterNames.Keys, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);

        public static readonly JsonEncodedText Kid = JsonEncodedText.Encode(JsonWebKeyParameterNames.Kid, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);

        public static readonly JsonEncodedText Kty = JsonEncodedText.Encode(JsonWebKeyParameterNames.Kty, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);

        public static readonly JsonEncodedText N = JsonEncodedText.Encode(JsonWebKeyParameterNames.N, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);

        public static JsonEncodedText Oth
        {
            get
            {
                if (!_othSet)
                {
                    _oth = JsonEncodedText.Encode(JsonWebKeyParameterNames.Oth, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _othSet = true;
                }

                return _oth;
            }
        }
        
        public static JsonEncodedText P
        {
            get
            {
                if (!_pSet)
                {
                    _p = JsonEncodedText.Encode(JsonWebKeyParameterNames.P, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _pSet = true;
                }

                return _p;
            }
        }
        public static JsonEncodedText Q
        {
            get
            {
                if (!_qSet)
                {
                    _q = JsonEncodedText.Encode(JsonWebKeyParameterNames.Q, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _qSet = true;
                }

                return _q;
            }
        }

        public static JsonEncodedText QI
        {
            get
            {
                if (!_qiSet)
                {
                    _qi = JsonEncodedText.Encode(JsonWebKeyParameterNames.QI, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _qiSet = true;
                }

                return _qi;
            }
        }

        public static readonly JsonEncodedText Use = JsonEncodedText.Encode(JsonWebKeyParameterNames.Use, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);

        public static readonly JsonEncodedText X5c = JsonEncodedText.Encode(JsonWebKeyParameterNames.X5c, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);

        public static readonly JsonEncodedText X5t = JsonEncodedText.Encode(JsonWebKeyParameterNames.X5t, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);

        public static JsonEncodedText X5tS256
        {
            get
            {
                if (!_x5tS256Set)
                {
                    _x5tS256 = JsonEncodedText.Encode(JsonWebKeyParameterNames.X5tS256, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _x5tS256Set = true;
                }

                return _x5tS256;
            }
        }

        public static JsonEncodedText X5u
        {
            get
            {
                if (!_x5uSet)
                {
                    _x5u = JsonEncodedText.Encode(JsonWebKeyParameterNames.X5u, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _x5uSet = true;
                }

                return _x5u;
            }
        }
        
        public static JsonEncodedText X
        {
            get
            {
                if (!_xSet)
                {
                    _x = JsonEncodedText.Encode(JsonWebKeyParameterNames.X, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _xSet = true;
                }

                return _x;
            }
        }

        public static JsonEncodedText Y
        {
            get
            {
                if (!_ySet)
                {
                    _y = JsonEncodedText.Encode(JsonWebKeyParameterNames.Y, JavaScriptEncoder.UnsafeRelaxedJsonEscaping);
                    _ySet = true;
                }

                return _y;
            }
        }
    }
}
