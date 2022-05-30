package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aveplen-bach/authentication-service/internal/controller"
	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	// =============================== database ===============================

	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("Failed to connect database")
	}

	db.AutoMigrate(&model.User{})

	// // ============================== frs client ==============================

	// frDialContext, frCancel := context.WithTimeout(context.Background(), 1*time.Second)
	// defer frCancel()

	// frsAddress := "localhost:7070"
	// frconn, err := grpc.DialContext(frDialContext, frsAddress, []grpc.DialOption{
	// 	grpc.WithBlock(),
	// 	grpc.WithTransportCredentials(insecure.NewCredentials()),
	// }...)

	// if err != nil {
	// 	log.Printf("Failed to connect to %s \n", frsAddress)
	// }

	// frc := face_recognition_service.NewFaceRecognitionClient(frconn)

	// // ============================== s3g client ==============================

	// s3DialContext, s3Cancel := context.WithTimeout(context.Background(), 1*time.Second)
	// defer s3Cancel()

	// s3gAddress := "localhost:9090"
	// s3gconn, err := grpc.DialContext(s3DialContext, s3gAddress, []grpc.DialOption{
	// 	grpc.WithBlock(),
	// 	grpc.WithTransportCredentials(insecure.NewCredentials()),
	// }...)

	// if err != nil {
	// 	log.Printf("Failed to connect to %s \n", s3gAddress)
	// }

	// s3gc := s3_grpc_gateway.NewS3GatewayClient(s3gconn)
	// fmt.Println(s3gc)

	// ================================ router ================================

	router := gin.Default()

	// =============================== handlers ===============================

	// login := controller.NewLoginController(db, frc)
	// register := controller.NewRegisterController(db, frc)

	login := controller.LoginController{
		Db: db,
	}

	register := controller.RegisterController{
		Db: db,
	}

	users := controller.UserController{
		Db: db,
	}

	// ================================ routes ================================

	router.OPTIONS("/api/v1/login", func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "http://localhost:8080")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")
	})

	router.POST("/api/v1/login", login.Post)
	router.GET("/api/v1/register", register.Get)
	router.GET("/api/v1/users", users.Get)
	router.GET("/", controller.Index)

	// =============================== shutdown ===============================

	srv := &http.Server{
		Addr:    ":8081",
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			log.Printf("listen: %s\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")
}
