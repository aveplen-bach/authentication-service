package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aveplen-bach/authentication-service/internal/controller"
	"github.com/aveplen-bach/authentication-service/internal/middleware"
	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/aveplen-bach/authentication-service/protos/s3file"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

	// ============================== fr client ===============================

	frDialContext, frCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer frCancel()

	frAddr := "localhost:8081"
	frcc, err := grpc.DialContext(frDialContext, frAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", frAddr, err))
	}

	fr := facerec.NewFaceRecognitionClient(frcc)
	logrus.Warn(fr)

	// ============================== s3g client ==============================

	s3DialContext, s3Cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer s3Cancel()

	s3addr := "localhost:9090"
	s3cc, err := grpc.DialContext(s3DialContext, s3addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", frAddr, err))
	}

	s3 := s3file.NewS3GatewayClient(s3cc)
	logrus.Warn(s3)

	// ================================ service ===============================

	ss := service.NewSessionService()
	ts := service.NewTokenService()

	s := service.NewService(db, ss, ts, fr, s3)

	// ================================ router ================================

	router := gin.Default()
	router.Use(middleware.Cors)

	// ============================== controller ==============================

	login := controller.NewLoginController(s)
	register := controller.NewRegisterController(s)
	users := controller.NewUserController(s)

	// ================================ routes ================================

	router.POST("/api/v1/login", login.LoginUser)
	router.POST("/api/v1/register", register.RegisterUser)
	router.POST("/api/v1/users", users.ListUsers)

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
