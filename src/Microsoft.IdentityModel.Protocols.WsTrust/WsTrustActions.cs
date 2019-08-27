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

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    public abstract class WsTrustActions<T> : WsTrustActions where T : new()
    {
        private static T _instance;

        public static T Instance
        {
            get
            {
                if (_instance == null)
                    _instance = new T();

                return _instance;
            }
        }
    }

    /// <summary>
    /// Provides actions for WS-Trust Feb2005, 1.3 and 1.4.
    /// </summary>
    public abstract class WsTrustActions
    {
        public static WsTrustFeb2005Actions TrustFeb2005 => WsTrustFeb2005Actions.Instance;

        public static WsTrust13Actions Trust13 => WsTrust13Actions.Instance;

        public static WsTrust14Actions Trust14 => WsTrust14Actions.Instance;

        public WsTrustActions() {}

        public string Cancel { get; protected set; }

        public string CancelFinal { get; protected set; }

        public string CancelRequest { get; protected set; }

        public string CancelResponse { get; protected set; }

        public string Issue { get; protected set; }

        public string IssueFinal { get; protected set; }

        public string IssueRequest { get; protected set; }

        public string IssueResponse { get; protected set; }

        public string Renew { get; protected set; }

        public string RenewFinal { get; protected set; }

        public string RenewRequest { get; protected set; }

        public string RenewResponse { get; protected set; }

        public string RequestSecurityContextToken { get; protected set; }

        public string RequestSecurityContextTokenCancel { get; protected set; }

        public string RequestSecurityContextTokenResponse { get; protected set; }

        public string RequestSecurityContextTokenResponseCancel { get; protected set; }

        public string Status { get; protected set; }

        public string Validate { get; protected set; }

        public string ValidateFinal { get; protected set; }

        public string ValidateRequest { get; protected set; }

        public string ValidateResponse { get; protected set; }
    }

    /// <summary>
    /// Provides actions for WS-Trust Feb2005.
    /// </summary>
    public class WsTrustFeb2005Actions : WsTrustActions<WsTrustFeb2005Actions>
    {
        public WsTrustFeb2005Actions()
        {
            Cancel = "http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel";
            CancelRequest = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Cancel";
            CancelResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Cancel";
            Issue = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue";
            IssueRequest = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue";
            IssueResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue";
            Renew = "http://schemas.xmlsoap.org/ws/2005/02/trust/Renew";
            RenewRequest = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Renew";
            RenewResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Renew";
            RequestSecurityContextToken = "http://schemas.xmlsoap.org/ws/2005/02/trust/RequestSecurityContextToken";
            RequestSecurityContextTokenCancel = "http://schemas.xmlsoap.org/ws/2005/02/trust/RequestSecurityContextTokenCancel";
            RequestSecurityContextTokenResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RequestSecurityContextTokenResponse";
            RequestSecurityContextTokenResponseCancel = "http://schemas.xmlsoap.org/ws/2005/02/trust/RequestSecurityContextTokenResponseCancel";
            Validate = "http://schemas.xmlsoap.org/ws/2005/02/trust/Validate";
            ValidateRequest = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Validate";
            ValidateResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Validate";
        }
    }

    /// <summary>
    /// Provides actions for WS-Trust 1.3.
    /// </summary>
    public class WsTrust13Actions : WsTrustActions<WsTrust13Actions>
    {
        public WsTrust13Actions()
        {
            Cancel = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel";
            CancelRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Cancel";
            CancelResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Cancel";
            CancelFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/CancelFinal";
            Issue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";
            IssueRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue";
            IssueResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Issue";
            IssueFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal";
            Renew = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Renew";
            RenewRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Renew";
            RenewResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Renew";
            RenewFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/RenewFinal";
            Status = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status";
            Validate = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate";
            ValidateRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Validate";
            ValidateResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Validate";
            ValidateFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/ValidateFinal";
        }
    }

    /// <summary>
    /// Provides actions for WS-Trust 1.4.
    /// </summary>
    public class WsTrust14Actions : WsTrustActions<WsTrust14Actions>
    {
        public WsTrust14Actions()
        {
            Cancel = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel";
            CancelRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Cancel";
            CancelResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Cancel";
            CancelFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/CancelFinal";
            Issue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";
            IssueRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue";
            IssueResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Issue";
            IssueFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal";
            Renew = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Renew";
            RenewRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Renew";
            RenewResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Renew";
            RenewFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/RenewFinal";
            Status = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status";
            Validate = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate";
            ValidateRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Validate";
            ValidateResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Validate";
            ValidateFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/ValidateFinal";
        }
    }
}
