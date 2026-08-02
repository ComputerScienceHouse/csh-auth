csh-auth v2
===========

An @ComputerScienceHouse authentication wrapper for Gin.
> **Note:** This documentation is for **v2** of the library.
> If you are looking for v1, please check the master branch.

## Usage

### Import csh-auth
```go
import cshauth "github.com/computersciencehouse/csh-auth/v2"
```

### Initialize your csh-auth object

```go
auth, err := cshauth.Init(
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

### Add csh-auth endpoints for user login

```go
r.GET("/auth/login", auth.HandleLogin) // This endpoint should match the path for loginURL
r.GET("/auth/callback", auth.HandleCallback) // This endpoint should match the path for callbackURL
r.POST("/auth/refresh", auth.HandleRefresh)
r.GET("/auth/logout", auth.HandleLogout)
```

### Add endpoints to be behind authentication

For client authentication, use `auth.CookieMiddleware()`  
For application authentication via Bearer tokens, use `auth.HeaderMiddleware()`.
The HeaderMiddleware only accepts the `Authorization` header with the format `Bearer: <JWT AccessToken>`.

For a single route: `r.GET("/locked/prize", auth.CookieMiddleware(), endpoint_hidden_prize)`  
This works because Gin will run the widest scope function to the most narrow scope function, in order. 

For more/all routes: Check the [Gin Middleware documentation](https://gin-gonic.com/en/docs/middleware/) page.

### Using refresh tokens

By default, a refresh token is stored in the browser's cookies. This token can be used to fetch a new auth token wihout having to redirect the user through SSO.

csh-auth handles this throught the refresh handler.
```go
router.POST("/auth/refresh", auth.HandleRefresh)
```

Whenever the auth token is expired, the browser should make a POST request to this endpoint. The server will update the browser's cookie with a new token.

This is particularly useful for SPAs, where the token validity isn't being check with every page interaction.

#### Example Implementation

The following is an example implementation that could be used in the browser.

```ts
const response = await fetch("/api/endpoint")

if (response.status === 401) { // token expired
    fetch('/auth/refresh', { // this will update the browser's cookie without requiring a page refresh
      method: 'POST',
      credentials: 'include',
    })
}
```

In a real application, the original request would typically be retried after a successful refresh. This example only demonstrates the basic refresh mechanism.

### Get user information
The information for a user is located at `gin.Context#Get("cshauth")`.
This information includes the JWT information as well.
