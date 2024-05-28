package auth

import (
	"github.com/gin-gonic/gin"
)

func (a *Authenticator) RegisterHandler(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.AbortWithStatusJSON(400, gin.H{"error": "Invalid request"})
		return
	}

	apiKey, err := AddAPIKey(API_KEY_FILE, user)
	if err != nil {
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal server error"})
		return
	}
	a.UserApiKeys[apiKey] = &user
	c.JSON(200, gin.H{"api_key": apiKey})
}

func (a *Authenticator) RegisterHandlers(g *gin.RouterGroup) {
	g.Use(a.RequireAdmin())
	g.POST("/register", a.RegisterHandler)
}
