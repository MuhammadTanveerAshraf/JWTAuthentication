using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuthentication.Controllers
{
    
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IJWTAuthenticationManager AuthenticationManager;

        public AccountController(IJWTAuthenticationManager authenticationManager)
        {
            AuthenticationManager = authenticationManager;
        }

        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "New Jersey", "Ohio", "New york" };
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public IActionResult Authenticate([FromBody] UserCred userCred)
        {
            var token = AuthenticationManager.Authenticate(userCred.UserName, userCred.Password);
            if (token is null)
            {
                return Unauthorized();
            }
            return Ok(token);
        }

        [Authorize]
        [HttpGet("GetNames")]
        public IActionResult GetNames()
        {
            var currentUser = HttpContext.User;

            var identity = User.Identity as ClaimsIdentity;
            if (identity != null)
            {
                IEnumerable<Claim> claims = identity.Claims;
                var name = claims.Where(x => x.Type == "name").FirstOrDefault().Value;
                return Ok(new { data = name });
            }
            return null;
        }
    }
}
