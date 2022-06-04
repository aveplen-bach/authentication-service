package service

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/aveplen-bach/authentication-service/internal/model"
	pb "github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/aveplen-bach/authentication-service/protos/s3file"
	"golang.org/x/crypto/pbkdf2"
	"gorm.io/gorm"
)

const (
	STAGE_CLIENT_CONN_INIT = iota + 1
	STAGE_SERVER_GEN_MAC
	STAGE_CLIENT_CRIDENTIALS
	STAGE_SERVER_TOKEN

	RandomStringLength = 16
)

type LoginService struct {
	db      *gorm.DB
	session *SessionService
	token   *TokenService
	ps      *PhotoService
	facerec pb.FaceRecognitionClient
	s3      s3file.S3GatewayClient
}

func NewLoginService(
	db *gorm.DB,
	session *SessionService,
	token *TokenService,
	ps *PhotoService,
	facerec pb.FaceRecognitionClient,
	s3 s3file.S3GatewayClient,
) *LoginService {

	return &LoginService{
		db:      db,
		session: session,
		facerec: facerec,
		token:   token,
		ps:      ps,
		s3:      s3,
	}
}

func (s *LoginService) Login(req *model.LoginRequest) (*model.LoginResponse, error) {
	switch req.Stage {
	case STAGE_CLIENT_CONN_INIT:
		return s.handleConnectionInit(req)

	case STAGE_CLIENT_CRIDENTIALS:
		return s.handleCredentials(req)

	default:
		return nil, errors.New("unknown stage")
	}
}

// client conn init stage

func (ls *LoginService) handleConnectionInit(loginRequest *model.LoginRequest) (*model.LoginResponse, error) {
	mac, err := cryptoutil.GenerateRandomString(RandomStringLength)
	if err != nil {
		return nil, err
	}

	sessionID := ls.session.Add(&model.SessionEntry{
		MessageAuthCode: mac,
	})

	return &model.LoginResponse{
		SessionID: sessionID,
		MAC:       mac,
		Stage:     STAGE_SERVER_GEN_MAC,
	}, nil
}

// client cridentials stage

func (ls *LoginService) handleCredentials(request *model.LoginRequest) (*model.LoginResponse, error) {
	// fetch user from db
	var user model.User
	if result := ls.db.Where("username = ?", request.Username).First(&user); result.Error != nil {
		return nil, result.Error
	}

	// get users session
	session, ok := ls.session.Get(request.SessionID)
	if !ok {
		return nil, errors.New("session does not exist")
	}

	// derive session key
	skey, err := deriveSessionKey([]byte(user.Password), session.MessageAuthCode)
	if err != nil {
		return nil, err
	}

	// save session key
	session.SessionKey = skey

	// decrypt photo
	encPhoto, err := base64.StdEncoding.DecodeString(request.EncryptedPhoto)
	if err != nil {
		return nil, err
	}

	ivDecoded, err := base64.StdEncoding.DecodeString(request.IV)
	if err != nil {
		return nil, err
	}

	photo, err := cryptoutil.DecryptAesCbc(encPhoto, skey, ivDecoded)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt photo: %w", err)
	}

	// check photo
	photoIsClose, err := ls.ps.PhotoIsCloseEnough(DeserializeFloats64(user.FFVector), photo)
	if err != nil {
		return nil, fmt.Errorf("cannot get distance between photots: %w", err)
	}
	if !photoIsClose {
		return nil, fmt.Errorf("photo is not close enough")
	}

	token, err := ls.token.GenerateToken(&user, request.SessionID)
	if err != nil {
		return nil, err
	}

	return &model.LoginResponse{
		Stage: STAGE_SERVER_TOKEN,
		JWT:   token,
	}, nil
}

func deriveSessionKey(password []byte, sessionMAC string) ([]byte, error) {
	sessionMACBytes, err := base64.StdEncoding.DecodeString(sessionMAC)
	if err != nil {
		return nil, err
	}

	key := pbkdf2.Key(password, sessionMACBytes, 4096, 16, sha1.New)

	return key, nil
}
