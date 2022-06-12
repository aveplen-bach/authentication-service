package server

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

	"github.com/aveplen-bach/authentication-service/internal/config"
	"github.com/aveplen-bach/authentication-service/internal/controller"
	"github.com/aveplen-bach/authentication-service/internal/middleware"
	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/aveplen-bach/authentication-service/internal/transport"
	"github.com/aveplen-bach/authentication-service/protos/auth"
	configpb "github.com/aveplen-bach/authentication-service/protos/config"
	"github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/aveplen-bach/authentication-service/protos/s3file"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Start(cfg config.Config) {
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

		cc, err := grpc.DialContext(dialContext, cfg.S3ClientConfig.Addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", cfg.S3ClientConfig.Addr, err))
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

		cc, err := grpc.DialContext(dialContext, cfg.FacerecClientConfig.Addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", cfg.FacerecClientConfig.Addr, err))
		}

		frch <- facerec.NewFaceRecognitionClient(cc)
	}()

	// ========================== config client ===========================
	cfgch := make(chan configpb.ConfigClient)
	wg.Add(1)
	go func() {
		wg.Done()

		dialContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		cc, err := grpc.DialContext(dialContext, cfg.ConfigClient.Addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", cfg.ConfigClient.Addr, err))
		}

		cfgch <- configpb.NewConfigClient(cc)
	}()

	// ============================== client wait =============================
	s3Client := <-s3ch
	facerecClient := <-frch
	configClient := <-cfgch

	wg.Wait()

	logrus.Warn("face recognition server: ", facerecClient)
	logrus.Warn("s3 gateway server: ", s3Client)
	logrus.Warn("config server: ", configClient)

	// ================================ service ===============================
	userService := service.NewUserService(db)
	sessionService := service.NewSessionService()
	tokenService := service.NewTokenService(cfg, sessionService)
	s3Service := service.NewS3Service(s3Client)
	facerecService := service.NewFacerecService(facerecClient)
	photoService := service.NewPhotoService(facerecService, s3Service)
	loginService := service.NewLoginService(userService, sessionService, tokenService, photoService)
	registerService := service.NewRegisterService(userService, photoService)
	logouService := service.NewLogoutService(tokenService, sessionService)
	helloService := service.NewHelloService(sessionService, tokenService)
	cryptoService := service.NewCryptoService(sessionService)

	// ============================= grpc server ==============================

	lis, err := net.Listen("tcp", cfg.ServerConfig.GrpcAddr)
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	auth.RegisterAuthenticationServer(grpcServer, transport.NewAuthenticationServer(tokenService, cryptoService))

	// ================================ router ================================
	r := gin.Default()
	r.Use(middleware.Cors())

	open := r.Group("/api/open")

	protected := r.Group("/api/protected")
	protected.Use(middleware.IncrementalToken(tokenService))

	admin := r.Group("/api/admin")
	admin.Use(middleware.IncrementalToken(tokenService))
	admin.Use(middleware.EndToEndEncryption(cryptoService))

	local := r.Group("/api/local")

	// ================================ routes ================================
	open.POST("/login", controller.LoginUser(loginService))

	protected.POST("/logout", controller.Logout(logouService))
	protected.POST("/test", func(c *gin.Context) {
		fmt.Println("what is going on?")
	})

	admin.POST("/user", controller.ListUsers(userService))
	admin.POST("/register", controller.RegisterUser(registerService))

	local.POST("/hello", controller.Hello(helloService))

	// =============================== shutdown ===============================
	srv := &http.Server{
		Addr:    cfg.ServerConfig.ApiAddr,
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