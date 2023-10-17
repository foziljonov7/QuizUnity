using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using QuizApi.Dtos;
using QuizApi.Entity;

namespace QuizApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    public static User user = new User();
    private readonly IConfiguration configuration;

    public AuthController(IConfiguration configuration)
    {
        this.configuration = configuration;
    }
    [HttpPost("Register")]
    public ActionResult<User> Register(UserDto dto)
    {
        string passwordHash 
            = BCrypt.Net.BCrypt.HashPassword(dto.Password);

        user.Username = dto.Username;
        user.PasswordHash = passwordHash;

        return Ok(user);
    }
    [HttpPost("Login")]
    public ActionResult<User> Login(UserDto dto)
    {
        if(user.Username != dto.Username)
            return BadRequest("User not found!");
        if(!BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
            return BadRequest("Wrong password!");

        var token = CreateToken(user);
        
        return Ok(token);
    }
    private string CreateToken(User user)
    {
        List<Claim> claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, user.Username)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
            configuration.GetSection("Settings:Token").Value!));

        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

        var token = new JwtSecurityToken(
            claims:claims,
            expires:DateTime.Now.AddDays(1),
            signingCredentials:cred);
        
        var jwt = new JwtSecurityTokenHandler().WriteToken(token);

        return jwt;
    }
}