using Newtonsoft.Json;

namespace FrontEnd.Authentication
{
    public class ExceptionHandlerMiddleware
    {
        private readonly RequestDelegate next;

        public ExceptionHandlerMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                //Write you logic
                string debug = "";
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context, ex);
            }
        }

        private static async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {

            context.Response.StatusCode = 500;
            //if (!IsRequestAPI(context))
            //{
            //    //when request api             
            //    context.Response.ContentType = "application/json";
            //    await context.Response.WriteAsync(JsonConvert.SerializeObject(new
            //    {
            //        State = 500,
            //        message = exception.Message
            //    }));
            //}
            //else
            //{
            //when request page 
            context.Response.Redirect("/Error");
            //}
        }
    }
}
