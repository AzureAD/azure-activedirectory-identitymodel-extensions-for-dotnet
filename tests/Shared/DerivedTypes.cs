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

// This file contains derived types that are usefull across multiple handlers / protocols.


namespace System.IdentityModel.Test
{
    using Collections.Generic;
    using Security.Claims;

#if ASPNET50CORE
    /// <summary>
    /// 
    /// </summary>
    public class DerivedClaim : Claim
    {
        string _dataString;
        byte[] _dataBytes;

        public DerivedClaim(Claim claim, string dataString, byte[] dataBytes)
            : base(claim)
        {
            _dataString = dataString;
            _dataBytes = dataBytes.CloneByteArray();
        }

        public DerivedClaim(DerivedClaim other)
            : this(other, (ClaimsIdentity)null)
        { }

        public DerivedClaim(DerivedClaim other, ClaimsIdentity subject)
            : base(other, subject)
        {
            _dataString = other._dataString;
            if (other._dataBytes != null)
                _dataBytes = other._dataBytes.CloneByteArray();
        }

        public DerivedClaim(BinaryReader reader)
            : this(reader, (ClaimsIdentity)null)
        { }

        public DerivedClaim(BinaryReader reader, ClaimsIdentity subject)
            : base(reader, subject)
        {

            Logger.LogInformation("DerivedClaim.ctor... base.SerializeName: " + base.SerializeName ?? "null");
            Logger.LogInformation("DerivedClaim.ctor... SerializeName: " + SerializeName ?? "null");
            if (string.IsNullOrWhiteSpace(base.SerializeName))
                return;

            _dataString = reader.ReadString();
            Int32 cb = reader.ReadInt32();
            if (cb > 0)
                _dataBytes = reader.ReadBytes(cb);
        }

        public byte[] DataBytes
        {
            get
            {
                return _dataBytes;
            }

            set
            {
                _dataBytes = value;
            }
        }

        public string DataString
        {
            get
            {
                return _dataString;
            }

            set
            {
                _dataString = value;
            }
        }

        protected override string SerializeName
        {
            get { return "Derived"; }
        }

        public string SerializedName
        {
            get { return SerializeName; }
        }

        public override Claim Clone()
        {
            return Clone((ClaimsIdentity)null);
        }

        public override Claim Clone(ClaimsIdentity identity)
        {
            return new DerivedClaim(this, identity);
        }

        public override void WriteTo(IO.BinaryWriter writer)
        {
            base.WriteTo(writer);
            Logger.LogInformation("SerializeName: " + SerializeName);
            writer.Write(_dataString);
            if (_dataBytes == null || _dataBytes.Length == 0)
            {
                writer.Write((Int32)0);
            }
            else
            {
                writer.Write((Int32)_dataBytes.Length);
                writer.Write(_dataBytes);
            }
        }
    }

    public class DerivedClaimsIdentity : ClaimsIdentity
    {
        string _dataString;
        byte[] _dataBytes;

        public DerivedClaimsIdentity(BinaryReader reader)
            : base(reader)
        {
            _dataString = reader.ReadString();
            Int32 cb = reader.ReadInt32();
            if (cb > 0)
                _dataBytes = reader.ReadBytes(cb);

        }

        public DerivedClaimsIdentity(IEnumerable<Claim> claims, string dataString, byte[] dataBytes)
            : base(claims)
        {
            _dataString = dataString;

            if (dataBytes != null && dataBytes.Length > 0)
                _dataBytes = dataBytes.CloneByteArray();
        }

        public string ClaimType { get; set; }

        public byte[] DataBytes
        {
            get
            {
                return _dataBytes;
            }

            set
            {
                _dataBytes = value;
            }
        }

        public string DataString
        {
            get
            {
                return _dataString;
            }

            set
            {
                _dataString = value;
            }
        }

        public override void WriteTo(BinaryWriter writer)
        {
            base.WriteTo(writer);
            writer.Write(_dataString);
            if (_dataBytes == null || _dataBytes.Length == 0)
            {
                writer.Write((Int32)0);
            }
            else
            {
                writer.Write((Int32)_dataBytes.Length);
                writer.Write(_dataBytes);
            }

            writer.Flush();
        }

        protected override Claim CreateClaim(BinaryReader reader)
        {
            DerivedClaim dc = new DerivedClaim(reader, this);
            if (string.IsNullOrWhiteSpace(dc.SerializedName))
            {
                Logger.LogInformation(" return (dc as Claim).Clone(this);");
                return (dc as Claim).Clone(this);
            }
            else
            {
                Logger.LogInformation(" return dc;");
                return dc;
            }
        }
    }

    public class DerivedClaimsPrincipal : ClaimsPrincipal
    {
    }
#else
    public class DerivedClaim : Claim
    {
        public DerivedClaim(Claim claim, string data, byte[] bytes)
            : base(claim.Value, claim.Type)
        {
        }
    }

    public class DerivedClaimsIdentity : ClaimsIdentity
    {
        public DerivedClaimsIdentity(IEnumerable<Claim> claims, string data, byte[] bytes)
            : base(claims)
        {

        }
    }

    public class DerivedClaimsPrincipal : ClaimsPrincipal
    {

    }
#endif

}