package controller

import (
	pb "github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type RegisterController struct {
	Db  *gorm.DB
	frc pb.FaceRecognitionClient
}

func NewRegisterController(db *gorm.DB, frc pb.FaceRecognitionClient) *RegisterController {
	return &RegisterController{
		Db:  db,
		frc: frc,
	}
}

func (l *RegisterController) Get(c *gin.Context) {
	c.SetCookie("jwt_token", "hello, I'm jwt-token", 3600, "/", "localhost", false, true)
}
