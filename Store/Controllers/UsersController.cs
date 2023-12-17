using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.Entity;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Store.Models;
using Store.Services;

namespace Store.Controllers
{
    public class UsersController : Controller
    {
        private eStoreConnection db = new eStoreConnection();

        public ActionResult Index()
        {
            return View(db.Users.ToList());
        }

        public ActionResult Login()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpPost]

        public ActionResult Login(User user)
        {


            var email = user.email;
            var password = user.pass;
            var keepLogin = true;
            bool keepLoginSession;

            keepLoginSession = keepLogin == true;

            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            {
                ModelState.AddModelError("", "Please enter valid username and password");

                return View();
            }
            var usr = db.Users.Where(u => u.email == user.email && u.pass == user.pass).FirstOrDefault();

            var appUserInfo = db.Users.Where(u => u.email == user.email && u.pass == user.pass
            ).FirstOrDefault();


            // Jwt Authentication code

            if (appUserInfo != null)
            {
                string encryptedPwd = password;

                var userPassword = appUserInfo.pass;
                var username = appUserInfo.email;
                if (encryptedPwd.Equals(userPassword) && username.Equals(email))
                {
                    var role = appUserInfo.name;
                    var jwtToken = Authentication.GenerateJWTAuthetication(email, role);
                    var validUserName = Authentication.ValidateToken(jwtToken);

                    if (string.IsNullOrEmpty(validUserName))
                    {
                                ModelState.AddModelError("", "Unauthorized login attempt ");

                        return View();
                    }

                    var cookie = new HttpCookie("jwt", jwtToken)
                    {
                        HttpOnly = true,
                        // Secure = true, // Uncomment this line if your application is running over HTTPS
                    };
                    Response.Cookies.Add(cookie);

                    Session["UserID"]= appUserInfo.id.ToString();
                    Session["UserName"] = appUserInfo.name.ToString();
                }
            }


                return RedirectToAction("loggedin");
            }
        [JwtAuthentication]
        public ActionResult LoggedIn()
        {
            if (Session["UserID"] != null)
            {
                return View();
            }
            else
            {
                return RedirectToAction("Login");
            }
        }
        // GET: Users/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // GET: Users/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Users/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "id,name,email,pass")] User user)
        {
            if (ModelState.IsValid)
            {
                db.Users.Add(user);
                db.SaveChanges();
                return RedirectToAction("Login");
            }

            return View(user);
        }

        // GET: Users/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // POST: Users/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "id,name,email,pass")] User user)
        {
            if (ModelState.IsValid)
            {
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            return View(user);
        }

        // GET: Users/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // POST: Users/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            User user = db.Users.Find(id);
            db.Users.Remove(user);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }

   }
