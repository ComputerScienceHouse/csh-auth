package csh_auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const ContextKey = "cshauth"
const CookieName = "Auth"
const ProviderURI = "https://sso.csh.rit.edu/auth/realms/csh"

var StateLookup map[string]string

type Auth struct {
	// clientID is the OIDC client ID.
	clientID string
	// clientSecret is the OIDC client secret.
	clientSecret string
	// serverURL is the "base" URL that this service is hosted from, e.g. "http://localhost:8000"
	serverURL string
	// authenticateURL is the URL for users to start the OAuth flow and login.
	// Commonly, this is set to something like ServerHost+"/auth/login"
	authenticateURL string
	// callbackURL is the URL that users will be redirected to at the end of the OAuth flow.
	// Commonly, this is set to something like ServerHost+"/auth/callback"
	callbackURL string
	// secure will be set if the serverURL contains https
	secure       bool
	oauth        oauth2.Config
	ctx          context.Context
	oidcProvider *oidc.Provider
	oidcCerts    jwt.VerificationKeySet
}

type UserInfo struct {
	Uuid     string   `json:"uuid"`
	Email    string   `json:"email"`
	Username string   `json:"preferred_username"`
	FullName string   `json:"name"`
	Groups   []string `json:"groups"`
}

type Claims struct {
	jwt.RegisteredClaims
	UserInfo
}

func Init(oidcClientID string, oidcClientSecret string, serverURL string, authenticateURL string, callbackURL string, scopes []string) (Auth, error) {
	auth := Auth{
		clientID:        oidcClientID,
		clientSecret:    oidcClientSecret,
		serverURL:       serverURL,
		authenticateURL: authenticateURL,
		callbackURL:     callbackURL,
		ctx:             context.Background(),
	}

	auth.secure = serverURL[0:5] == "https"

	auth.oidcCerts = getVerificationKeys()

	var err error
	auth.oidcProvider, err = oidc.NewProvider(auth.ctx, ProviderURI)
	if err != nil {
		log.Error("Failed to create OIDC Provider")
		log.Error(err)
		return auth, err
	}
	scopes = append(scopes, oidc.ScopeOpenID)
	auth.oauth = oauth2.Config{
		ClientID:     auth.clientID,
		ClientSecret: auth.clientSecret,
		Endpoint:     auth.oidcProvider.Endpoint(),
		RedirectURL:  auth.callbackURL,
		Scopes:       scopes,
	}

	StateLookup = make(map[string]string)

	return auth, nil
}

// Route functions

func (auth *Auth) HandleLogin(c *gin.Context) {
	auth.oauth.RedirectURL = auth.callbackURL + "?referer=" + c.Query("referer")
	state := rand.Text()
	ref := rand.Text()
	c.SetCookie("ref", ref, int(time.Minute), "", "", auth.secure, true)
	StateLookup[ref] = state
	c.Redirect(http.StatusFound, auth.oauth.AuthCodeURL(state))
}

func (auth *Auth) HandleCallback(c *gin.Context) {
	ref, err := c.Cookie("ref")
	if err != nil {
		log.Error("no callback ref cookie")
		c.Redirect(http.StatusFound, auth.authenticateURL)
		return
	}
	state, ok := StateLookup[ref]
	if !ok {
		log.Error("callback ref not found")
		c.Redirect(http.StatusFound, auth.authenticateURL)
		return
	}
	if c.Query("state") != state {
		log.Error("state does not match")
		c.Redirect(http.StatusFound, auth.authenticateURL)
		return
	}

	oauthJWT, err := auth.oauth.Exchange(auth.ctx, c.Query("code"))
	if err != nil {
		log.Error("failed to exchange token")
		return
	}

	c.SetCookie(CookieName, oauthJWT.AccessToken, int(oauthJWT.ExpiresIn), "", "", false, true)
	c.Redirect(http.StatusFound, c.Query("referer"))
}

// Middleware functions

func (auth *Auth) CookieMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie(CookieName)
		if err != nil {
			log.Error(CookieName, "cookie not found")
			c.Redirect(http.StatusFound, auth.authenticateURL+"?referer="+c.Request.URL.String())
			return
		}
		err = auth.setGinContext(c, cookie)
		if err != nil {
			log.Error("failed to set context")
			return
		}
	}
}

func (auth *Auth) HeaderMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.Request.Header.Get("Authorization")
		if header == "" {
			c.Header("WWW-Authenticate", "Authentication Required")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if header[0:8] != "Bearer: " {
			c.Header("WWW-Authenticate", "Bad Authentication Header")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		err := auth.setGinContext(c, header)
		if err != nil {
			log.Error("failed to set context")
			return
		}

	}
}

// Utility functions

func (auth *Auth) setGinContext(c *gin.Context, tokenString string) error {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return auth.oidcCerts, nil
	})
	if err != nil {
		log.Error("failed to parse token", err)
		return err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		c.Set(ContextKey, claims)
		return nil
	}

	log.Error("failed parsing JWT claims")
	return errors.New("failed parsing JWT claims")
}

func getVerificationKeys() jwt.VerificationKeySet {
	client := http.DefaultClient
	res, err := client.Get(ProviderURI + "/protocol/openid-connect/certs")
	if err != nil {
		log.Error("Failed to get verification keys", err)
		return jwt.VerificationKeySet{}
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		log.Error("Failed to read verification keys", err)
		return jwt.VerificationKeySet{}
	}
	res.Body.Close()
	ret := jwt.VerificationKeySet{}
	err = json.Unmarshal(data, &ret)
	if err != nil {
		log.Error("Failed to unmarshal verification keys", err)
		return jwt.VerificationKeySet{}
	}
	return ret
}
