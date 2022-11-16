using Microsoft.AspNetCore.Http.Extensions;
using System.Security.Cryptography;
using System.Text;

namespace ServerB.Middlewares
{
    public class ValidTokenMiddleware
    {
        private readonly RequestDelegate next;
        private const string APIKEY = "XApiKey";
        private const string APITIME = "TimeStamp";
        private const string SECRET_KEY = "SecretKey";


        public ValidTokenMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (!context.Request.Headers.TryGetValue(APIKEY, out var extractedToken))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Token was not provided");
                return;
            }
            if (!context.Request.Headers.TryGetValue(APITIME, out var extractedTime))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Request send time was not provided");
                return;
            }
            var appSettings = context.RequestServices.GetRequiredService<IConfiguration>();
            var secretKey = appSettings.GetValue<string>(SECRET_KEY);

            String uri = context.Request.Path.ToString();
            String authenticationDataString = (String.Format("{0}{1}", uri, extractedTime));

            string hashedToken = ComputeHash(secretKey, authenticationDataString);

            if (!extractedToken.ToString().Equals(hashedToken))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized client");
                return;
            }
            await next(context);
        }

        private static string ComputeHash(String secretKey, String authenticationDataString)
        {
            HMACSHA512 hmac = new HMACSHA512(Convert.FromBase64String(secretKey));

            Byte[] authenticationData = UTF8Encoding.GetEncoding("utf-8").GetBytes(authenticationDataString);

            var hashedToken = hmac.ComputeHash(authenticationData);
            return Convert.ToBase64String(hashedToken);
        }
    }
}
