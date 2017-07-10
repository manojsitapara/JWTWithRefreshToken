using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using JsonWebTokensWebApi.Domain;
using JsonWebTokensWebApi.Models;

namespace JsonWebTokensWebApi.Controllers
{
    public class DataController : ApiController
    {
        [AllowAnonymous]
        [HttpGet]
        [Route("api/data/GetGuestUserName")]
        public IHttpActionResult GetGuestUserName()
        {
            return Ok("Hello Guest !!!");
        }



        [Authorize(Roles = "patient")]
        [HttpGet]
        [Route("api/data/GetPatientUserName")]
        public IHttpActionResult GetAuthenticatedPatientUserName()
        {
            var identity = (ClaimsIdentity)User.Identity;
            return Ok("Hello " + identity.Name);
        }


        [Authorize(Roles = "provider")]
        [HttpGet]
        [Route("api/data/GetProviderUserName")]
        public IHttpActionResult GetAuthenticatedProviderUserName()
        {
            var identity = (ClaimsIdentity)User.Identity;

            var roles = identity.Claims
                        .Where(c => c.Type == ClaimTypes.Role)
                        .Select(c => c.Value);

            ClaimsPrincipal principal = Request.GetRequestContext().Principal as ClaimsPrincipal;
            if (principal != null)
            {
                var userFullName = principal.Claims.Single(c => c.Type == ClaimTypes.Name).Value;

                return Ok("Hello " + userFullName + " Role: " + string.Join(",", roles.ToList()));
            }
            else
                return NotFound();
        }


        [Authorize]
        [HttpPost]
        [Route("api/data/ChangePassword")]
        public IHttpActionResult ChangeProviderPassword(ChangePasswordBindingModel model)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userName = GetUserName();

            hPayDomain hPayDomain = new hPayDomain();

            bool isPasswordChanged = hPayDomain.ChangePassword(userName, model.OldPassword, model.NewPassword);


            if (isPasswordChanged == true)
            {
                return Ok();
            }
            else
            {
                return BadRequest("Old password is not correct.");
            }

        }



        [HttpPost]
        [Route("api/data/ForgetPassword")]
        public IHttpActionResult ForgetPassword(string userName)
        {


            hPayDomain hPayDomain = new hPayDomain();

            bool isPasswordReset = hPayDomain.ForgetPassword(userName);


            if (isPasswordReset == true)
            {
                return Ok();
            }
            else
            {
                return BadRequest("Old password is not correct.");
            }

        }





        private string GetUserName()
        {
            var identity = (ClaimsIdentity)User.Identity;

            var usernameFromClaims = identity.Claims
                .Where(c => c.Type == Constants.Username)
                .Select(c => c.Value);


            string userName = string.Join(",", usernameFromClaims.ToList());
            return userName;
        }



    }
}
