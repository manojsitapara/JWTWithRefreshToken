using System;
using System.Collections.Generic;
using System.Data.Entity.Migrations;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using JsonWebTokensWebApi.EntityFramework;
using System.Text;

namespace JsonWebTokensWebApi.Domain
{
    //hPay_Demo_HSAEntities
    public class hPayDomain
    {
        public User AuthenticateUser(string userName, string password)
        {
            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                var hPayUser = hPayEntities.Users.FirstOrDefault(u => u.UserLogin == userName && u.Pswd == password && u.IsApproved == true);
                return hPayUser;
            }
        }

        public User GetUser(string userName)
        {

            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {

                var hPayUser = hPayEntities.Users.FirstOrDefault(u => u.UserLogin == userName);
                hPayEntities.Entry<User>(hPayUser).Reload();
                return hPayUser;
            }
        }






        public bool ChangePassword(string userName, string oldPassword, string newPassword)
        {

            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                var hPayUser = hPayEntities.Users.FirstOrDefault(u => u.UserLogin == userName && u.Pswd == oldPassword);
                var status = false;
                if (hPayUser != null)
                {
                    hPayUser.Pswd = newPassword;
                    hPayEntities.Users.AddOrUpdate(hPayUser);
                    hPayEntities.SaveChanges();
                    status = true;
                }
                return status;
            }


        }



        public bool ForgetPassword(string userName)
        {
            string password = string.Empty;
            bool status = false;
            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                var hPayUser = hPayEntities.Users.FirstOrDefault(u => u.UserLogin == userName);
                if (hPayUser != null)
                {
                    ResetPassword(userName);

                    status = true;
                }
                return status;
            }

        }





        public bool ResetPassword(string userLogin)
        {
            bool isSuccessful = false;
            User user = GetUser(userLogin);
            if (user != null && (user.Deactivated == null || user.Deactivated == false))
            {
                try
                {
                    string resetPasswordToken = GetNewPasswordToken();

                    user.PasswordResetExpiration = DateTime.Now.AddDays(1);
                    user.PasswordResetToken = resetPasswordToken;

                    using (var db = new hPay_Demo_HSAEntities())
                    {
                        db.Entry(user).State = System.Data.Entity.EntityState.Modified;
                        db.SaveChanges();

                    }

                    SendPasswordViaEmail(resetPasswordToken);
                    isSuccessful = true;
                }
                catch (Exception ex)
                {
                    isSuccessful = false;
                }
                
            }

            return isSuccessful;


        }


        public static string GetNewPasswordToken()
        {
            string tempPassword = Guid.NewGuid().ToString("N").ToLower()
                      .Replace("1", "").Replace("o", "").Replace("0", "")
                      .Substring(0, 10);
            return tempPassword;
        }



        public Client GetClient(string clientId)
        {
            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                var hPayClient = hPayEntities.Clients.FirstOrDefault(u => u.Id == clientId);
                return hPayClient;
            }


        }


        public bool AddRefreshToken(RefreshToken refreshToken)
        {
            bool status = false;

            try
            {
                using (var db = new hPay_Demo_HSAEntities())
                {
                    var existingToken = db.RefreshTokens.Where(r => r.Subject == refreshToken.Subject && r.ClientId == refreshToken.ClientId).SingleOrDefault();

                    if (existingToken != null)
                    {
                        db.RefreshTokens.Attach(existingToken);
                        db.RefreshTokens.Remove(existingToken);
                        db.SaveChanges();

                    }

                    RefreshToken _refreshToken = new RefreshToken();
                    _refreshToken.Id = refreshToken.Id;
                    _refreshToken.Subject = refreshToken.Subject;
                    _refreshToken.ClientId = refreshToken.ClientId;
                    _refreshToken.IssuedUtc = refreshToken.IssuedUtc;
                    _refreshToken.ExpiresUtc = refreshToken.ExpiresUtc;
                    _refreshToken.ProtectedTicket = refreshToken.ProtectedTicket;



                    db.RefreshTokens.Add(_refreshToken);
                    db.SaveChanges();
                    status = true;

                }
            }
            catch (Exception ex)
            {
                string exception = ex.Message;
                status = false;
            }
            return status;
        }


        public RefreshToken GetRefreshToken(string refreshTokenId)
        {
            //DateTime currentDateTimeInUtcFormaTime = TimeZoneInfo.ConvertTimeToUtc(System.DateTime.Now);
            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                var refreshToken =
                    hPayEntities.RefreshTokens.FirstOrDefault(
                        u => u.Id == refreshTokenId );
                return refreshToken;
            }



        }

        public bool DeleteRefreshTokenByRefreshTokenId(string refreshTokenId)
        {
            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {

                var refreshToken = hPayEntities.RefreshTokens.FirstOrDefault(u => u.Id == refreshTokenId);
                var status = false;
                if (refreshToken != null)
                {
                    hPayEntities.RefreshTokens.Remove(refreshToken);
                    hPayEntities.SaveChanges();
                    status = true;
                }
                return status;
            }
        }




        public bool UpdateUserLoginInFlag(string userName, bool isUserLogIn)
        {
            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                var user = hPayEntities.Users.FirstOrDefault(u => u.UserLogin == userName);
                var status = false;
                if (user != null)
                {
                    user.IsLoggedIn = isUserLogIn;


                    hPayEntities.Entry(user).State = System.Data.Entity.EntityState.Modified;
                    hPayEntities.SaveChanges();
                    status = true;

                }
                return status;
            }
        }


        public bool IsUserLoggedIn(string userName)
        {
            bool isUserLoggedIn = false;
            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                var hPayUser = hPayEntities.Users.FirstOrDefault(u => u.UserLogin == userName);
                if (hPayUser.IsLoggedIn != null)
                {
                    if (hPayUser.IsLoggedIn == true)
                    {
                        isUserLoggedIn = true;
                    }
                    else
                    {
                        isUserLoggedIn = false;
                    }

                }

            }
            return isUserLoggedIn;
        }


        public void DeleteRefreshToken(RefreshToken token)
        {
            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                hPayEntities.RefreshTokens.Attach(token);
                hPayEntities.RefreshTokens.Remove(token);
                //hPayEntities.RefreshTokens.Remove(token);
                hPayEntities.SaveChanges();

            }
        }


        public bool ChangeResetPassword(string userName, string tempPassword, string newPassword)
        {
            bool resetChangePasswordStatus = false;

            using (var hPayEntities = new hPay_Demo_HSAEntities())
            {
                var hPayUser = hPayEntities.Users.FirstOrDefault(u => u.UserLogin == userName && u.PasswordResetToken == tempPassword && u.IsApproved == true);

                if (hPayUser != null)
                {
                    hPayUser.Pswd = newPassword;
                    hPayEntities.Entry(hPayUser).State = System.Data.Entity.EntityState.Modified;
                    hPayEntities.SaveChanges();
                    resetChangePasswordStatus = true;
                }
            }
            return resetChangePasswordStatus;
        }

        private void SendPasswordViaEmail(string password)
        {

            var fromAddress = new MailAddress("xoproject2014@gmail.com", "hPay");
            var toAddress = new MailAddress("manojs@cxcnetwork.com", "Manoj Sitapara");
            const string fromPassword = "Xocxc@123";
            const string subject = "hPay: Forget Password";

            StringBuilder msg = new StringBuilder("Your password has been reset. Your temporary password is ").Append(password);
            msg.Append("\r\n\r\nPlease note that this password will expire after 24 hours. So please click on the below link to change your password at the earliest: ");

            msg.Append("\r\n\r\nPlease contact the hPay administrator if you need help with this. ");

            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromAddress.Address, fromPassword)
            };
            using (var message = new MailMessage(fromAddress, toAddress)
            {
                Subject = subject,
                Body = msg.ToString()
            })
            {
                smtp.Send(message);
            }
        }
    }
}