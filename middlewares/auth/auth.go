package auth

import (
	"github.com/gin-gonic/gin"
)

const (
	API_KEY_FILE   = "api_keys.txt"
	API_KEY_HEADER = "HACTAR_API_KEY"
)

type Role string

const (
	Admin       Role = "admin"
	RegularUser Role = "user"
)

type User struct {
	Email string `json:"email"`
	Role  Role   `json:"role"`
}

type Authenticator struct {
	UserApiKeys map[string]*User
}

func NewAuthenticator() (*Authenticator, error) {
	apiKeys, err := LoadAPIKeys(API_KEY_FILE)
	if err != nil {
		return nil, err
	}
	return &Authenticator{
		UserApiKeys: apiKeys,
	}, nil
}

func (a *Authenticator) RequireAuth(role Role) gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		a.UserApiKeys, err = LoadAPIKeys(API_KEY_FILE)
		if err != nil {
			c.AbortWithStatusJSON(500, gin.H{"error": "Internal server error"})
			return
		}

		apiKey := c.GetHeader(API_KEY_HEADER)

		user, ok := a.UserApiKeys[apiKey]
		if !ok || user.Role != role {
			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
			return
		}
		c.Set("user", user)

		c.Next()
	}
}

func (a *Authenticator) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		a.RequireAuth(Admin)(c)
	}
}

func (a *Authenticator) RequireUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		a.RequireAuth(RegularUser)(c)
	}
}
