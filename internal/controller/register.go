package controller

import (
	pb "github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type registerController struct {
	db  *gorm.DB
	frc pb.FaceRecognitionClient
}

func NewRegisterController(db *gorm.DB, frc pb.FaceRecognitionClient) *registerController {
	return &registerController{
		db:  db,
		frc: frc,
	}
}

func (l *registerController) Register(c *gin.Context) {
	c.SetCookie("jwt_token", "hello, I'm jwt-token", 3600, "/", "localhost", false, true)
}
