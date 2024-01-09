# What's that?

The experimental solution to validate capabilities of [YARP](https://github.com/microsoft/reverse-proxy) as a gateway core for microservices.

# Features

The gateway & libraries together implement the following features:

1. External auth token / credentials are decoupled from internal auth ticket ([OWASP recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html#recommendation-on-how-to-implement-identity-propagation)).
2. Internal auth ticket is crypto-protected using [ASP.NET Core Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction). This doesn't follow [the OWASP pattern with STS](https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html#using-a-data-structures-signed-by-a-trusted-issuer), but looks convenient for .NET-only microservice application.
3. All the cookies are crypto-protected using [ASP.NET Core Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction).
4. Unauthorized and authorized sessions are managed according to [OWASP recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
5. Authorization logic is decoupled from API gateway – it was taken out to the auth service.
6. The session data is accessible from any microservice (for both authorized and unauthorized sessions).
7. Support for all the standard [ASP.NET Core Authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/introduction) mechanincs in the distributed environment, including roles and policies.
8. Extra capability to keep permissions in a session data (outside of a ticket) to solve HTTP headers bloat problem.

# Microservices / gateway

[ApiGateway](./api-gateway) – the ASP.NET core gateway based on YARP. The responsibilities of this component are:

- Routing.
- Edge level authorization.
- Login / Logout external endpoint.
- Maintaining session cookies.

Serving of the pages is extra capability of the `ApiGateway` implemented solely for demo purpose.

[AuthorizationService](./authorization-service) – the ASP.NET Core microservice responsible for authorization & establishing an authorized session on the backend.

[WeatherService](./weather-service) & [YetAnotherService](./yet-another-service) – examples of application microservices.

# Libraries

[Distributed.Session](./libraries/distributed-session) – the session library for microservices made by analogy of original [ASP.NET Core Session Middleware](https://github.com/dotnet/aspnetcore/tree/main/src/Middleware/Session/src), which supports distributed session over [IDistributedCache](https://learn.microsoft.com/en-us/aspnet/core/performance/caching/distributed). The only difference is that our `Distributed.Session` doesn't maintain cookies since doing this is a gateway responsibility.

[Distributed.Authentication](./libraries/distributed-authentication) – the authentication library for microservices. To propagate identity of an authenticated user we pass serialized [AuthenticationTicket](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationticket) (ASP.NET Core thing) by [HTTP bearer auth-scheme](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization). The ticket is protected cryptographically, not being a JWT.

[Distributed.Permissions](./libraries/distributed-permissions) – the library to pass permissions using a distributed session. The experimental thing, which can help solving the HTTP headers bloat problem.

# Quick start

1. To start [Redis](https://redis.io/) & [Redis Commander](https://joeferner.github.io/redis-commander/) in Docker run:

```bash
docker-compose up
```

2. To check Redis in browser you can navigate to http://localhost:8081/.

3. Open solution in VS and launch.

4. Visit https://localhost:7272/ and navigate through menu links. It's suggested to use browser's developer tools (press F12) to check network requests & replies and cookies.

5. To login (at `/auth/login`) use the following credentials:

   - Username `John` & password `pwd` for basic user.
   - Username `Bob` & password `power` for a member of 'power' role.

You can also try wrong username & password (up to 3 times before lock) to see how anonymous session is used to count attempts.

# Scenarios to check

## Anonymous user

Not being authorized you can access the following resources:

- Page 1 (`/demo/page1`) – the page served by `DemoController` on the gateway.
- Yet 1 (`/api/yet/one`) – the API method served by `YetAnotherService` behind the gateway.

You'll get successful responses (200) in both cases.

Each time you access Yet 1 (`/api/yet/one`) the request counter is incremented and returned in response. This demonstrates unauthorized session, check how it works in the [TestController of YetAnotherService](./yet-another-service/Controllers/TestController.cs).

Next, try to access Weather API method (`/api/weather`) – you'll get 401 from the gateway since the `weather` route is protected by an authorization policy in the YARP configuration (`ReverseProxy` segment). Check the [appsettings.json of the ApiGateway](./api-gateway/appsettings.json).

Then try Yet 2 method (`/api/yet/two`) – you'll get 401 from the service because the `yet` route isn't protected at the gateway level (unlike the `weather`), but the controller method has `[Authorize]` attribute.

Finally, try to access Page 2 (`/demo/page2`) – you'll be redirected to login page (`/auth/login`) by the gateway authentication handler because it distinguishes between page paths and APIs. Check how it works in the [ApiGateway authentication handler](./api-gateway/AuthenticationHandler.cs).

If you try to login using wrong username / password you'll be warned about wrong password and after 3 attempts locked (until unauthorized session expiration). Check [AuthController of AuthorizationService](./authorization-service/Controllers/AuthController.cs).

## John (basic user)

Login using username `John` and password `pwd`.

Open the Page 2 (`/demo/page2`) – you'll get successful (200) response.

Check Yet 1 (`/api/yet/one`) – you'll see that request counter starts from 1 again because you have a new (authorized) session.

Check Weather (`/api/weather`), Yet 2 (`/api/yet/two`) – both are accessible since no role / permission required. Any authorized user can access those methods.

Check Yet 3 (`/api/yet/three`) – you'll get 403 from the microservice because its method is protected with `[Authorize(Roles = "power")]` attribute, but John isn't a member of 'power' role. Check the [TestController of YetAnotherService](./yet-another-service/Controllers/TestController.cs) and the [handler in the distributed authentication library](./libraries/distributed-authentication/AuthenticationHandler.cs).

Finally, check Yet 4 (`/api/yet/four`) – you'll see that you don't have "Alcohol.Drink" permission. The condition `HttpContext.HasPermission("Alcohol.Drink")` in the method `Four()` of [TestController of YetAnotherService](./yet-another-service/Controllers/TestController.cs) isn't satisfied.

## Bob (power user)

Logout and re-login using username `Bob` and password `power`.

Test all the same paths you checked under `John`, see the difference:

- Request counter starts from 1 since you are authorized again.
- Yet 3 (`/api/yet/three`) is accessible because Bob is a member of the 'power' role.
- Yet 4 (`/api/yet/four`) returns slightly different response since Bob has "Alcohol.Drink" permission.

Check the [AuthController of AuthorizationService](./authorization-service/Controllers/AuthController.cs) to understand how the permissions are set.