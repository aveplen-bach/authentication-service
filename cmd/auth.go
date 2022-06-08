package main

import (
	"context"
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
	"github.com/aveplen-bach/authentication-service/internal/middleware"
	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/aveplen-bach/authentication-service/internal/transport"
	"github.com/aveplen-bach/authentication-service/protos/auth"
	"github.com/aveplen-bach/authentication-service/protos/config"
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

	// ============================== s3g client ==============================

	var wg sync.WaitGroup

	s3ch := make(chan s3file.S3GatewayClient)
	wg.Add(1)
	go func() {
		wg.Done()

		dialContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		s3Addr := "localhost:30031"
		cc, err := grpc.DialContext(dialContext, s3Addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", s3Addr, err))
		}

		s3ch <- s3file.NewS3GatewayClient(cc)
	}()

	// ============================== fr client ===============================

	frch := make(chan facerec.FaceRecognitionClient)
	wg.Add(1)
	go func() {
		wg.Done()

		dialContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		frAddr := "localhost:30032"
		cc, err := grpc.DialContext(dialContext, frAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", frAddr, err))
		}

		frch <- facerec.NewFaceRecognitionClient(cc)
	}()

	// ========================== config client ===========================

	cfgch := make(chan config.ConfigClient)
	wg.Add(1)
	go func() {
		wg.Done()

		dialContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		cfgAddr := "localhost:30033"
		cc, err := grpc.DialContext(dialContext, cfgAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", cfgAddr, err))
		}

		cfgch <- config.NewConfigClient(cc)
	}()

	// ============================== client wait =============================

	s3 := <-s3ch
	fr := <-frch
	cfg := <-cfgch

	wg.Wait()

	logrus.Warn("face recognition server: ", fr)
	logrus.Warn("s3 gateway server: ", s3)
	logrus.Warn("config server: ", cfg)

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

	lis, err := net.Listen("tcp", "localhost:30030")
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

	open := r.Group("/api/open")

	admin := r.Group("/api/admin")
	admin.Use(middleware.IncrementalToken(ts))
	admin.Use(middleware.AuthCheck(as))
	admin.Use(middleware.EndToEndEncryption(ts, ss))

	local := r.Group("/api/local")
	// ================================ routes ================================

	protected.GET("/authenticated", controller.Authenticated(ts))
	protected.GET("/users", controller.ListUsers(us))
	protected.POST("/register", controller.RegisterUser(rs))

	open.GET("/authenticated", controller.Authenticated(ts))
	open.POST("/login", controller.LoginUser(ls))

	admin.GET("/user", controller.ListUsers(us))
	admin.POST("/register", controller.RegisterUser(rs))

	local.POST("/hello", controller.Hello(ss, ts))

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
