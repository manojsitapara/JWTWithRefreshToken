using System;
using System.Threading.Tasks;
using System.Web.Http;
using JsonWebTokensWebApi.Format;
using JsonWebTokensWebApi.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;

[assembly: OwinStartup(typeof(JsonWebTokensWebApi.Startup))]

namespace JsonWebTokensWebApi
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            HttpConfiguration config = new HttpConfiguration();

            // Web API routes
            config.MapHttpAttributeRoutes();

            ConfigureOAuth(app);

            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);

            app.UseWebApi(config);

        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            var issuer = "http://jwtauthzsrv.azurewebsites.net";
            var audience = "099153c2625149bc8ecb3e85e03f0022";
            var secret = TextEncodings.Base64Url.Decode("IxrAjDoa2FqElO7IhrSrUJELhUckePEPVpaePlS_Xaw");


            OAuthAuthorizationServerOptions oAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                //For Dev enviroment only (on production should be AllowInsecureHttp = false)
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/oauth2/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30),
                Provider = new CustomOAuthProvider(),
                AccessTokenFormat = new CustomJwtFormat(issuer),
                RefreshTokenProvider = new SimpleRefreshTokenProvider(),

            };

            // OAuth 2.0 Bearer Access Token Generation
            app.UseOAuthAuthorizationServer(oAuthServerOptions);



            
            // Api controllers with an [Authorize] attribute will be validated with JWT
            app.UseJwtBearerAuthentication(
                new JwtBearerAuthenticationOptions
                {
                    AuthenticationMode = AuthenticationMode.Active,
                    AllowedAudiences = new[] { audience },
                    IssuerSecurityTokenProviders = new IIssuerSecurityTokenProvider[]
                    {
                        new SymmetricKeyIssuerSecurityTokenProvider(issuer, secret)
                    }
                });


        }
    }
}
