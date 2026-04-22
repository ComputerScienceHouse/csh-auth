csh-auth
========

An @ComputerScienceHouse authentication wrapper for Gin.

## Usage

1. Create a CSHAuth Struct

```
csh := csh_auth.CSHAuth{}
```

2. Initialize your CSHAuth object

```
csh.Init(
    /* oidc_client_id */,       // The OIDC client ID
    /* oidc_client_secret */,   // The OIDC client Secret
    /* jwt_secret */,           // I just used a random sequence of > 16 characters
    /* state */,                // I just used a random sequence of > 16 characters
    /* server_host */,          // The domain your application will run from
    /* redirect_uri */,         // The OIDC redirect URI
    /* auth_uri */,             // The relative path for your authentication endpoint
)
```

3. Add required CSHAuth endpoints

```
r.GET("/auth/login", csh.AuthRequest) // This endpoint should match auth_uri
r.GET("/auth/callback", csh.AuthCallback) // This endpoint should match the relative portion of redirect_uri
r.GET("/auth/logout", csh.AuthLogout)
```

4. Add endpoints to be behind authentication

a. Use a wrapper function
```
r.GET("/hidden/prize", csh.AuthWrapper(endpoint_hidden_prize))
```

b. Use middleware.

For a single route: `r.GET("/hidden/prize", csh.AuthWrapper, endpoint_hidden_prize)`  
This works because Gin will run the widest scope function to the most narrow scope function, in order. 

For more/all routes: Check the [Gin Middleware documentation](https://gin-gonic.com/en/docs/middleware/) page.

