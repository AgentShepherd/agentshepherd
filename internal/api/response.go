package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Success sends a JSON success response
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, data)
}

// Error sends a JSON error response
func Error(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
}

// ListResponse is a standard response for list endpoints
type ListResponse struct {
	Total int         `json:"total"`
	Items interface{} `json:"items,omitempty"`
}

// ErrorResponse is a standard error response
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}
