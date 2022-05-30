package controller

import (
	"fmt"

	pb "github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type loginController struct {
	db  *gorm.DB
	frc pb.FaceRecognitionClient
}

func NewLoginController(db *gorm.DB, frc pb.FaceRecognitionClient) *loginController {
	return &loginController{
		db:  db,
		frc: frc,
	}
}

func (l *loginController) Login(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "http://localhost:8080")
	c.Header("Access-Control-Allow-Credentials", "true")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
	c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")

	req := &gin.H{}
	c.BindJSON(req)
	fmt.Println(*req)
	c.SetCookie("jwt_token", "hello, I'm jwt-token", 3600, "/", "localhost", false, true)
}
