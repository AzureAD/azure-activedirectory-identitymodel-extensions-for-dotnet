//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace System.IdentityModel.Test
{
    /// <summary>
    /// Summary description for RemoteDomainManager.
    /// </summary>
    [Serializable]
    public abstract class RemoteDomainManager : MarshalByRefObject
    {
        public static T CreateInDomain<T>( AppDomain domain )
        {
            return (T)domain.CreateInstanceAndUnwrap( typeof( T ).Assembly.FullName, typeof( T ).FullName );
        }

        public abstract void Start( string testCase );
        public abstract void Stop();
        public abstract void TearDown();
    }
}
