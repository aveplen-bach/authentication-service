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
	logrus.Info("connecting to database")
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("Failed to connect database")
	}

	db.AutoMigrate(&model.User{})

	// ============================== s3g client ==============================
	var wg sync.WaitGroup

	logrus.Info("connecting s3 gateway")
	s3ch := make(chan s3file.S3GatewayClient)
	wg.Add(1)
	go func() {
		wg.Done()

		dialContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cc, err := grpc.DialContext(dialContext, cfg.S3ClientConfig.Addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", cfg.S3ClientConfig.Addr, err))
		}

		s3ch <- s3file.NewS3GatewayClient(cc)
	}()

	// ============================== fr client ===============================
	logrus.Info("connecting facerec service")
	frch := make(chan facerec.FaceRecognitionClient)
	wg.Add(1)
	go func() {
		wg.Done()

		dialContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cc, err := grpc.DialContext(dialContext, cfg.FacerecClientConfig.Addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", cfg.FacerecClientConfig.Addr, err))
		}

		frch <- facerec.NewFaceRecognitionClient(cc)
	}()

	// ========================== config client ===========================
	logrus.Info("connecting config service")
	cfgch := make(chan configpb.ConfigClient)
	wg.Add(1)
	go func() {
		wg.Done()

		dialContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	logrus.Info("creating services")
	userService := service.NewUserService(db)
	sessionService := service.NewSessionService()
	tokenService := service.NewTokenService(cfg, sessionService)
	s3Service := service.NewS3Service(s3Client)
	facerecService := service.NewFacerecService(facerecClient)
	configService := service.NewConfigService(configClient)
	photoService := service.NewPhotoService(facerecService, s3Service, configService)
	loginService := service.NewLoginService(userService, sessionService, tokenService, photoService)
	registerService := service.NewRegisterService(userService, photoService)
	logouService := service.NewLogoutService(tokenService, sessionService)
	helloService := service.NewHelloService(sessionService, tokenService)
	cryptoService := service.NewCryptoService(sessionService)

	// ============================= grpc server ==============================
	logrus.Info("creating grpc server")
	lis, err := net.Listen("tcp", cfg.ServerConfig.GrpcAddr)
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	auth.RegisterAuthenticationServer(grpcServer, transport.NewAuthenticationServer(tokenService, cryptoService))

	// ================================ router ================================
	logrus.Info("creating router")
	r := gin.Default()
	r.Use(middleware.Cors())

	open := r.Group("/api/open")

	prot := r.Group("/api/prot")
	prot.Use(middleware.Token(tokenService))

	encr := r.Group("/api/encr")
	encr.Use(middleware.Token(tokenService))
	encr.Use(middleware.Encrypted(cryptoService))

	locl := r.Group("/api/locl")
	locl.Use(middleware.Localhost())

	// ================================ routes ================================
	logrus.Info("registering routes")

	open.POST("/login", controller.Login(loginService))
	prot.GET("/logout", controller.Logout(logouService))

	encr.GET("/users", middleware.Admin(), controller.ListUsers(userService))
	encr.POST("/users", middleware.Admin(), controller.RegisterUser(registerService))

	locl.GET("/hello", controller.Hello(helloService))

	// =============================== shutdown ===============================
	srv := &http.Server{
		Addr:    cfg.ServerConfig.ApiAddr,
		Handler: r,
	}

	go func() {
		logrus.Infof("listening: %s\n", grpcServer)
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
