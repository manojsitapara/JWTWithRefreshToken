using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using JsonWebTokensWebApi.Domain;
using JsonWebTokensWebApi.EntityFramework;
using Microsoft.Owin.Security.Infrastructure;

namespace JsonWebTokensWebApi.Provider
{
    public class SimpleRefreshTokenProvider : IAuthenticationTokenProvider
    {
        private hPayDomain _hPayDomain;
        public SimpleRefreshTokenProvider()
        {
            _hPayDomain = new hPayDomain();
        }
        public async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            var clientid = context.Ticket.Properties.Dictionary["clientid"];

            if (string.IsNullOrEmpty(clientid))
            {
                return;
            }

            var refreshTokenId = Guid.NewGuid().ToString("n");
            var refreshTokenLifeTime = context.OwinContext.Get<string>("clientRefreshTokenLifeTime");


            
            var token = new RefreshToken()
            {
                Id = refreshTokenId,
                ClientId = clientid,
                Subject = context.Ticket.Identity.Name,
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(Convert.ToDouble(refreshTokenLifeTime))
            };



            //Set the desired lifetime of refresh token
            context.Ticket.Properties.IssuedUtc = token.IssuedUtc;
            context.Ticket.Properties.ExpiresUtc = token.ExpiresUtc;

            //Protected Ticket column contains signed string which contains a serialized representation for the ticket for specific user
            //In other words it contains all the claims and ticket properties for this user. 
            //The Owin middle-ware will use this string to build the new access token auto-magically
            token.ProtectedTicket = context.SerializeTicket();

            var result = _hPayDomain.AddRefreshToken(token);
            if (result)
            {
                context.SetToken(refreshTokenId);
            }

            return;
        }

        public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            Receive(context);
        }

        public void Create(AuthenticationTokenCreateContext context)
        {
            throw new NotImplementedException();
        }

        public void Receive(AuthenticationTokenReceiveContext context)
        {
            var refreshToken = _hPayDomain.GetRefreshToken(context.Token);

            if (refreshToken == null)
            {
                // Return user with status code 400, if refresh token is empty
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                context.Response.ReasonPhrase = "Please login again to gain application access.";
            }
            else
            {
                //AuthenticationTokenReceiveContext DeserializeTicket data and assign back to AuthenticationTicket
                //Protected Ticket column which contains signed string which contains a serialized representation for the ticket for specific user
                //In other words it contains all the claims and ticket properties for this user. 
                context.DeserializeTicket(refreshToken.ProtectedTicket);
                _hPayDomain.DeleteRefreshTokenByRefreshTokenId(context.Token);

            }

        }
    }
}