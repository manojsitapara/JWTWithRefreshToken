//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace JsonWebTokensWebApi.EntityFramework
{
    using System;
    using System.Collections.Generic;
    
    public partial class RefreshToken
    {
        public string Id { get; set; }
        public string Subject { get; set; }
        public string ClientId { get; set; }
        public Nullable<System.DateTime> IssuedUtc { get; set; }
        public Nullable<System.DateTime> ExpiresUtc { get; set; }
        public string ProtectedTicket { get; set; }
    }
}
