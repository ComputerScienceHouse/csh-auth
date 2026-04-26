csh-auth
========

An @ComputerScienceHouse authentication wrapper for Gin.

## Usage

1. Initialize your csh-auth object

```
auth := csh-auth.Init(
    clientID            // the OIDC client ID
    clientSecret        // the OIDC client secret
    serverURL           // the "base" URL that this service is hosted from, e.g. "http://localhost:8000"
    loginURL            // the URL for users to start the OAuth flow and login.
                        // Commonly, this is set to something like ServerHost+"/auth/login"
    callbackURL         // the URL that users will be redirected to at the end of the OAuth flow.
                        // Commonly, this is set to something like ServerHost+"/auth/callback"
    scopes              // pick scopes the application will use
)
```

2. Add csh-auth endpoints for user login

```
r.GET("/auth/login", auth.HandleLogin) // This endpoint should match the path for loginURL
r.GET("/auth/callback", auth.HandleCallback) // This endpoint should match the path for callbackURL
r.GET("/auth/logout", auth.HandleLogout)
```

3. Add endpoints to be behind authentication

For client authentication, use `auth.CookieMiddleware()`  
For application authentication via Bearer tokens, use `auth.HeaderMiddleware()`.
The HeaderMiddleware only accepts the `Authorization` header with the format `Bearer: <JWT AccessToken>`.

For a single route: `r.GET("/locked/prize", auth.CookieMiddleware(), endpoint_hidden_prize)`  
This works because Gin will run the widest scope function to the most narrow scope function, in order. 

For more/all routes: Check the [Gin Middleware documentation](https://gin-gonic.com/en/docs/middleware/) page.

