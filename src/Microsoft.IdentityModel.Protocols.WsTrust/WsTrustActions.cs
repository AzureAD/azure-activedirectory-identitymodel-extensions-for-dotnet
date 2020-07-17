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
    ///// <summary>
    ///// Abstract class for singleton pattern for multipule WsTrust versions for Actions.
    ///// </summary>
    ///// <typeparam name="T"></typeparam>
    //public abstract class WsTrustActions<T> : WsTrustActions where T : new()
    //{
    //    private T _instance;

    //    /// <summary>
    //    /// Implements singleton pattern.
    //    /// </summary>
    //    public T Instance
    //    {
    //        get
    //        {
    //            if (_instance == null)
    //                _instance = new T();

    //            return _instance;
    //        }
    //    }
    //}

    /// <summary>
    /// Values for Actions for WsTrust Feb2005, 1.3 and 1.4.
    /// </summary>
    public abstract class WsTrustActions
    {
        /// <summary>
        /// Gets the an instance of WsTrust Feb2005 Actions.
        /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
        /// </summary>
        public static WsTrustFeb2005Actions TrustFeb2005 => new  WsTrustFeb2005Actions();

        /// <summary>
        /// Gets the an instance of WsTrust 1.3 Actions.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        public static WsTrust13Actions Trust13 => new WsTrust13Actions();

        /// <summary>
        /// Gets the an instance of Trust 1.4 Actions.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html </para>
        /// </summary>
        public static WsTrust14Actions Trust14 => new WsTrust14Actions();

        /// <summary>
        /// Gets the Cancel action.
        /// </summary>
        public string Cancel { get; protected set; }

        /// <summary>
        /// Gets the CancelFinal action.
        /// </summary>
        public string CancelFinal { get; protected set; }

        /// <summary>
        /// Gets the CancelRequest action.
        /// </summary>
        public string CancelRequest { get; protected set; }

        /// <summary>
        /// Gets the CancelResponse action.
        /// </summary>
        public string CancelResponse { get; protected set; }

        /// <summary>
        /// Gets the Issue action.
        /// </summary>
        public string Issue { get; protected set; }

        /// <summary>
        /// Gets the IssueFinal action.
        /// </summary>
        public string IssueFinal { get; protected set; }

        /// <summary>
        /// Gets the IssueRequest action.
        /// </summary>
        public string IssueRequest { get; protected set; }

        /// <summary>
        /// Gets the IssueResponse action.
        /// </summary>
        public string IssueResponse { get; protected set; }

        /// <summary>
        /// Gets the Renew action.
        /// </summary>
        public string Renew { get; protected set; }

        /// <summary>
        /// Gets the RenewFinal action.
        /// </summary>
        public string RenewFinal { get; protected set; }

        /// <summary>
        /// Gets the RenewRequest action.
        /// </summary>
        public string RenewRequest { get; protected set; }

        /// <summary>
        /// Gets the RenewResponse action.
        /// </summary>
        public string RenewResponse { get; protected set; }

        /// <summary>
        /// Gets the Status action.
        /// </summary>
        public string Status { get; protected set; }

        /// <summary>
        /// Gets the Validate action.
        /// </summary>
        public string Validate { get; protected set; }

        /// <summary>
        /// Gets the ValidateFinal action.
        /// </summary>
        public string ValidateFinal { get; protected set; }

        /// <summary>
        /// Gets the ValidateRequest action.
        /// </summary>
        public string ValidateRequest { get; protected set; }

        /// <summary>
        /// Gets the ValidateResponse action.
        /// </summary>
        public string ValidateResponse { get; protected set; }
    }

    /// <summary>
    /// Provides string values for WsTrust Feb2005 Actions.
    /// </summary>
    public class WsTrustFeb2005Actions : WsTrustActions
    {
        /// <summary>
        /// Creates an instance of <see cref="WsTrustFeb2005Actions"/>.
        /// <para>The property <see cref="WsTrustActions.TrustFeb2005"/>  maintains a singleton instance of actions for WsTrust Feb2005</para>
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
    /// Provides string values for WsTrust 1.3 Actions.
    /// </summary>
    public class WsTrust13Actions : WsTrustActions
    {
        /// <summary>
        /// Creates an instance of <see cref="WsTrust13Actions"/>.
        /// <para>The property <see cref="WsTrustActions.Trust13"/>   maintains a singleton instance of actions for WsTrust 1.3</para>
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
    /// Provides string values for WsTrust 1.4 Actions.
    /// </summary>
    public class WsTrust14Actions : WsTrustActions
    {
        /// <summary>
        /// Creates an instance of <see cref="WsTrust14Actions"/>.
        /// <para>The property <see cref="WsTrustActions.Trust14"/>   maintains a singleton instance of actions for WsTrust 1.4</para>
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
