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
    [Authorize]
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

        [AllowAnonymous]
        [HttpGet("GetToken")]
        public IActionResult GetToken()
        {
            string key = "my_secret_key";
            var issuer = "http://mysite.com";
            var securitKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key));
            var credentials = new SigningCredentials(securitKey, SecurityAlgorithms.HmacSha256);

            var permClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("valid", "1"),
                new Claim("userId", "1"),
                new Claim("name", "Tanveer")
            };

            var token = new JwtSecurityToken(issuer,
                issuer,
                permClaims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: credentials
                );

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            return Ok(new { token = jwtToken });
        }
    }
}
