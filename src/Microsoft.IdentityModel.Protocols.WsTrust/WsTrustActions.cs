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

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Constants: WS-Trust Actions.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public abstract class WsTrustActions
    {
        /// <summary>
        /// Gets WS-Trust Feb2005 Actions.
        /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
        /// </summary>
        public static WsTrustFeb2005Actions TrustFeb2005 { get; } = new WsTrustFeb2005Actions();

        /// <summary>
        /// Gets WS-Trust 1.3 Actions.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        public static WsTrust13Actions Trust13 { get; } = new WsTrust13Actions();

        /// <summary>
        /// Gets WS-Trust 1.4 Actions.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html </para>
        /// </summary>
        public static WsTrust14Actions Trust14 { get; } = new WsTrust14Actions();

        /// <summary>
        /// Gets Cancel Action.
        /// </summary>
        public string Cancel { get; protected set; }

        /// <summary>
        /// Gets CancelFinal Action.
        /// </summary>
        public string CancelFinal { get; protected set; }

        /// <summary>
        /// Gets CancelRequest Action.
        /// </summary>
        public string CancelRequest { get; protected set; }

        /// <summary>
        /// Gets CancelResponse Action.
        /// </summary>
        public string CancelResponse { get; protected set; }

        /// <summary>
        /// Gets Issue Action.
        /// </summary>
        public string Issue { get; protected set; }

        /// <summary>
        /// Gets IssueFinal Action.
        /// </summary>
        public string IssueFinal { get; protected set; }

        /// <summary>
        /// Gets IssueRequest Action.
        /// </summary>
        public string IssueRequest { get; protected set; }

        /// <summary>
        /// Gets IssueResponse Action.
        /// </summary>
        public string IssueResponse { get; protected set; }

        /// <summary>
        /// Gets Renew Action.
        /// </summary>
        public string Renew { get; protected set; }

        /// <summary>
        /// Gets RenewFinal Action.
        /// </summary>
        public string RenewFinal { get; protected set; }

        /// <summary>
        /// Gets RenewRequest Action.
        /// </summary>
        public string RenewRequest { get; protected set; }

        /// <summary>
        /// Gets RenewResponse Action.
        /// </summary>
        public string RenewResponse { get; protected set; }

        /// <summary>
        /// Gets Status Action.
        /// </summary>
        public string Status { get; protected set; }

        /// <summary>
        /// Gets Validate Action.
        /// </summary>
        public string Validate { get; protected set; }

        /// <summary>
        /// Gets ValidateFinal Action.
        /// </summary>
        public string ValidateFinal { get; protected set; }

        /// <summary>
        /// Gets ValidateRequest Action.
        /// </summary>
        public string ValidateRequest { get; protected set; }

        /// <summary>
        /// Gets ValidateResponse Action.
        /// </summary>
        public string ValidateResponse { get; protected set; }
    }

    /// <summary>
    /// Constants: WS-Trust Feb2005 Actions.
    /// </summary>
    public class WsTrustFeb2005Actions : WsTrustActions
    {
        /// <summary>
        /// Instantiates WS-Trust Feb2005 Actions.
        /// </summary>
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
            Validate = "http://schemas.xmlsoap.org/ws/2005/02/trust/Validate";
            ValidateRequest = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Validate";
            ValidateResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Validate";
        }
    }

    /// <summary>
    /// Constants: WS-Trust 1.3 Actions.
    /// </summary>
    public class WsTrust13Actions : WsTrustActions
    {
        /// <summary>
        /// Instantiates WS-Trust 1.3 Actions.
        /// </summary>
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
            RenewResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Renew";
            RenewFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/RenewFinal";
            Status = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status";
            Validate = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate";
            ValidateRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Validate";
            ValidateResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Validate";
            ValidateFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/ValidateFinal";
        }
    }

    /// <summary>
    /// Constants: WS-Trust 1.4 Actions.
    /// </summary>
    public class WsTrust14Actions : WsTrustActions
    {
        /// <summary>
        /// Instantiates WS-Trust 1.4 Actions.
        /// </summary>
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
            RenewResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Renew";
            RenewFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/RenewFinal";
            Status = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status";
            Validate = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate";
            ValidateRequest = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Validate";
            ValidateResponse = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Validate";
            ValidateFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/ValidateFinal";
        }
    }
}
