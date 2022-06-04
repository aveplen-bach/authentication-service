package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
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

	var wg sync.WaitGroup

	frch := make(chan facerec.FaceRecognitionClient)
	wg.Add(1)
	go func() {
		wg.Done()

		frDialContext, frCancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer frCancel()

		frAddr := "localhost:8082"
		frcc, err := grpc.DialContext(frDialContext, frAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", frAddr, err))
		}

		frch <- facerec.NewFaceRecognitionClient(frcc)
	}()

	// ============================== s3g client ==============================

	s3ch := make(chan s3file.S3GatewayClient)
	wg.Add(1)
	go func() {
		wg.Done()

		s3DialContext, s3Cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer s3Cancel()

		s3Addr := "localhost:8083"
		s3cc, err := grpc.DialContext(s3DialContext, s3Addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", s3Addr, err))
		}

		s3ch <- s3file.NewS3GatewayClient(s3cc)
	}()

	// ============================== client coll =============================

	fr := <-frch
	s3 := <-s3ch

	wg.Wait()

	logrus.Warn("s3 gateway server: ", s3)
	logrus.Warn("face recognition server: ", fr)

	// ================================ service ===============================

	us := service.NewUserService(db)
	ss := service.NewSessionService()
	ts := service.NewTokenService()
	s3s := service.NewS3Service(s3)
	fs := service.NewFacerecService(fr)

	ps := service.NewPhotoService(fs, s3s)

	as := service.NewAuthService(ts)
	ls := service.NewLoginService(us, ss, ts, ps)
	rs := service.NewRegisterService(us, ps)

	// ================================ router ================================

	router := gin.Default()
	router.Use(middleware.Cors())
	router.Use(middleware.IncrementalToken(ts))
	router.Use(middleware.AuthCheck(as))
	router.Use(middleware.EndToEndEncryption(ts, ss))

	// ================================ routes ================================

	router.POST("/api/login", controller.LoginUser(ls))
	router.POST("/api/register", controller.RegisterUser(rs))

	router.GET("/api/user", controller.ListUsers(us))

	// =============================== shutdown ===============================

	srv := &http.Server{
		Addr:    ":8081",
		Handler: router,
	}

	go func() {
		logrus.Infof("listening: %s\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			logrus.Warn(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logrus.Warn("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logrus.Fatal("Server forced to shutdown:", err)
	}

	logrus.Warn("server exited")
}
