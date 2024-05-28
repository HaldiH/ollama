package auth

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	API_KEY_FILE = "api_keys.txt"
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

func (a *Authenticator) Authenticate(c *gin.Context) {
	var err error
	a.UserApiKeys, err = LoadAPIKeys(API_KEY_FILE)
	if err != nil {
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal server error"})
		return
	}

	authHeader := c.GetHeader("Authorization")

	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	apiKey := strings.TrimPrefix(authHeader, "Bearer ")

	user, ok := a.UserApiKeys[apiKey]
	if !ok {
		c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
		return
	}
	c.Set("email", user.Email)
	c.Set("role", user.Role)
	c.Set("authenticator", a)
	fmt.Println("role", user.Role)

	c.Next()
}

func GetAuthenticator(c *gin.Context) *Authenticator {
	return c.MustGet("authenticator").(*Authenticator)
}

func RequireRole(required Role) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := GetRole(c)

		if role != Admin && role != required {
			c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden"})
			return
		}
	}
}

func RequireAdmin(c *gin.Context) {
	RequireRole(Admin)(c)
}

func RequireUser(c *gin.Context) {
	RequireRole(RegularUser)(c)
}
