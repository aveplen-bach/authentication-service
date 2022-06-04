package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/aveplen-bach/authentication-service/internal/controller"
	"github.com/aveplen-bach/authentication-service/internal/ginutil"
	"github.com/aveplen-bach/authentication-service/internal/middleware"
	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/aveplen-bach/authentication-service/internal/transport"
	"github.com/aveplen-bach/authentication-service/protos/auth"
	"github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/aveplen-bach/authentication-service/protos/s3file"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type HelloRequest struct {
	UserID int `json:"userId"`
}

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

	// ============================== client wait =============================

	fr := <-frch
	s3 := <-s3ch

	wg.Wait()

	logrus.Warn("s3 gateway server: ", s3)
	logrus.Warn("face recognition server: ", fr)

	// ================================ service ===============================

	us := service.NewUserService(db)
	ss := service.NewSessionService()
	ts := service.NewTokenService(ss)
	s3s := service.NewS3Service(s3)
	fs := service.NewFacerecService(fr)
	ps := service.NewPhotoService(fs, s3s)
	as := service.NewAuthService(ts)
	ls := service.NewLoginService(us, ss, ts, ps)
	rs := service.NewRegisterService(us, ps)
	s := service.NewService(ts)

	// ============================= grpc server ==============================

	lis, err := net.Listen("tcp", "localhost:30031")
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	auth.RegisterAuthenticationServer(grpcServer, transport.NewAuthenticationServer(s))

	// ================================ router ================================

	r := gin.Default()
	r.Use(middleware.Cors())

	protected := r.Group("/api/protected")
	protected.Use(middleware.AuthCheck(as))
	protected.Use(middleware.IncrementalToken(ts))
	protected.Use(middleware.EndToEndEncryption(ts, ss))

	open := r.Group("/api/open")

	// ================================ routes ================================

	protected.POST("/register", controller.RegisterUser(rs))
	protected.GET("/users", controller.ListUsers(us))
	protected.POST("/incremental", func(c *gin.Context) {
		token, err := ginutil.ExtractToken(c)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		next, err := ts.NextToken(token)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "successfully created token",
			"token":  next,
		})
	})

	open.POST("/api/login", controller.LoginUser(ls))
	open.POST("/hello", func(c *gin.Context) {
		var req HelloRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		session, err := ss.New(uint(req.UserID))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		session.SessionKey = pbkdf2.Key([]byte("password"), []byte("salt"), 4096, 16, sha1.New)
		session.IV = make([]byte, 16)

		token, err := ts.GenerateToken(uint(req.UserID))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "successfully created token",
			"token":  token,
			"key":    base64.StdEncoding.EncodeToString(session.SessionKey),
			"iv":     base64.StdEncoding.EncodeToString(session.IV),
		})
	})

	// =============================== shutdown ===============================

	srv := &http.Server{
		Addr:    ":8081",
		Handler: r,
	}

	go func() {
		grpcServer.Serve(lis)
	}()

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

	grpcServer.Stop()

	if err := srv.Shutdown(ctx); err != nil {
		logrus.Fatal("Server forced to shutdown:", err)
	}

	logrus.Warn("server exited")
}
