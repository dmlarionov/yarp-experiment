using System;
namespace ApiGateway.Models
{
	public class LoginPageModel
	{
        public string Message { get; set; } = string.Empty;
        public LoginModel LoginModel { get; set; } = new LoginModel();

        public LoginPageModel() { }

        public LoginPageModel(string message)
        {
            Message = message;
        }

        public LoginPageModel(LoginModel loginModel)
        {
            LoginModel = loginModel;
        }

        public LoginPageModel(string message, LoginModel loginModel)
		{
			Message = message;
			LoginModel = loginModel;
		}
	}
}

