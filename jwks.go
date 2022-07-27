package auth

import (
	"context"
	"fmt"
	"log"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// func NewRouter() *gin.Engine {
// 	r := gin.New()
// 	r.Use(gin.Logger())
// 	r.Use(gin.CustomRecovery(func(c *gin.Context, err any) {
// 		c.JSON(http.StatusBadRequest, err.(error).Error())
// 		c.Abort()
// 	}))

// 	r.POST("upload", handlers.StoreFile)
// 	r.GET("files/:filename", handlers.GetFile)
// 	r.DELETE("files/:filename", handlers.DeleteFile)

// 	return r
// }

func getKeyFunc(context context.Context, jwksURL string) *keyfunc.JWKS {
	options := keyfunc.Options{
		Ctx: context,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval: 0,
	}

	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		log.Fatalf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}
	return jwks
}

var jwksURL = "https://evilmerchant.b2clogin.com/2a80bde3-5842-4619-bc0c-bf0c754b32d0/b2c_1a_federate/discovery/v2.0/keys"

var EvilmerchantClaims = "EVMClaims"

func EvilmerchantAuth() gin.HandlerFunc {
	jwks := getKeyFunc(context.Background(), jwksURL)

	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.AbortWithError(401, fmt.Errorf("no authorization token found"))
			return
		}
		jwtB64 := authHeader[7:]

		token, err := jwt.Parse(jwtB64, jwks.Keyfunc)
		if err != nil {
			ctx.AbortWithError(401, fmt.Errorf("failed to parse the JWT.\nError: %s", err.Error()))
			return
		}

		if !token.Valid {
			ctx.AbortWithError(401, fmt.Errorf("invalid token"))
			return
		}

		ctx.Set(EvilmerchantClaims, token.Claims)
	}
}
