package service

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/util"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
)

const (
	STAGE_CLIENT_CONN_INIT = iota + 1
	STAGE_SERVER_GEN_MAC
	STAGE_CLIENT_CRIDENTIALS
	STAGE_SERVER_TOKEN

	LoginMACLength = 16
)

type LoginService struct {
	us      *UserService
	session *SessionService
	token   *TokenService
	ps      *PhotoService
}

func NewLoginService(
	us *UserService,
	session *SessionService,
	token *TokenService,
	ps *PhotoService,
) *LoginService {

	return &LoginService{
		us:      us,
		session: session,
		token:   token,
		ps:      ps,
	}
}

func (s *LoginService) Login(req *model.LoginRequest) (*model.LoginResponse, error) {
	logrus.Info("handling login request")
	switch req.Stage {
	case STAGE_CLIENT_CONN_INIT:
		return s.handleConnectionInit(req)

	case STAGE_CLIENT_CRIDENTIALS:
		return s.handleCredentials(req)

	default:
		logrus.Error("unkown login stage")
		return nil, errors.New("unknown login stage")
	}
}

func (ls *LoginService) handleConnectionInit(lreq *model.LoginRequest) (*model.LoginResponse, error) {
	logrus.Info("handling login connection init")
	user, err := ls.us.GetUserByUsername(lreq.Username)
	if err != nil {
		logrus.Errorf("could not get user with given username: %w", err)
		return nil, fmt.Errorf("could not get user with given username: %w", err)
	}

	lmac, err := cryptoutil.GenerateRandomString(LoginMACLength)
	if err != nil {
		logrus.Errorf("could not generate random string: %w", err)
		return nil, fmt.Errorf("could not generate random string: %w", err)
	}

	ls.session.Destroy(user.ID)
	session, err := ls.session.New(user.ID)
	if err != nil {
		logrus.Errorf("could not initialize session: %w", err)
		return nil, fmt.Errorf("could not initialize session: %w", err)
	}
	session.LoginMAC = lmac

	return &model.LoginResponse{
		Stage:    STAGE_SERVER_GEN_MAC,
		LoginMAC: lmac,
	}, nil
}

func (ls *LoginService) handleCredentials(lreq *model.LoginRequest) (*model.LoginResponse, error) {
	logrus.Info("handling login credentials")
	user, err := ls.us.GetUserByUsername(lreq.Username)
	if err != nil {
		logrus.Errorf("could not find user with given username: %w", err)
		return nil, fmt.Errorf("could not find user with given username: %w", err)
	}

	session, err := ls.session.Get(user.ID)
	if err != nil {
		logrus.Errorf("could not get user session: %w", err)
		return nil, fmt.Errorf("could not get user session: %w", err)
	}

	skey, err := deriveSessionKey([]byte(user.Password), session.LoginMAC)
	if err != nil {
		logrus.Errorf("could not derive session key: %w", err)
		return nil, fmt.Errorf("could not derive session key: %w", err)
	}

	session.Key = skey

	if lreq.EncryptedPhoto == nil {
		logrus.Errorf("photo cipher is not present")
		return nil, fmt.Errorf("photo cipher is not present")
	}

	photoCipher, err := base64.StdEncoding.DecodeString(*lreq.EncryptedPhoto)
	if err != nil {
		logrus.Errorf("could not decode photo cipher")
		return nil, fmt.Errorf("could not decode photo cipher")
	}

	if lreq.IV == nil {
		logrus.Errorf("iv cipher is not present")
		return nil, fmt.Errorf("iv cipher is not present")
	}

	iv, err := base64.StdEncoding.DecodeString(*lreq.IV)
	if err != nil {
		logrus.Errorf("could not decode iv")
		return nil, fmt.Errorf("could not decode iv")
	}
	session.IV = iv

	photo, err := cryptoutil.DecryptAesCbc(photoCipher, skey, iv)
	if err != nil {
		logrus.Errorf("could not decrypt photo: %w", err)
		return nil, fmt.Errorf("could not decrypt photo: %w", err)
	}

	photoVector, err := ls.ps.ExtractVector(photo)
	if err != nil {
		logrus.Errorf("could not extract vector: %w", err)
		return nil, fmt.Errorf("could not extract vector: %w", err)
	}

	photoIsCloseEnough, err := ls.ps.PhotoIsCloseEnough(util.DeserializeFloats64(user.FFVector), photoVector)
	if err != nil {
		logrus.Errorf("cannot get distance between photots: %w", err)
		return nil, fmt.Errorf("cannot get distance between photots: %w", err)
	}

	if !photoIsCloseEnough {
		logrus.Errorf("photo is not close enough")
		return nil, fmt.Errorf("photo is not close enough")
	}

	token, err := ls.token.Construct(user.ID, user.Admin)
	if err != nil {
		logrus.Errorf("could not construct token: %w", err)
		return nil, fmt.Errorf("could not construct token: %w", err)
	}

	return &model.LoginResponse{
		Stage: STAGE_SERVER_TOKEN,
		Token: token,
	}, nil
}

func deriveSessionKey(password []byte, sessionMAC string) ([]byte, error) {
	sessionMACBytes, err := base64.StdEncoding.DecodeString(sessionMAC)
	if err != nil {
		logrus.Errorf("could not decode session mac: %w", err)
		return nil, fmt.Errorf("could not decode session mac: %w", err)
	}

	key := pbkdf2.Key(password, sessionMACBytes, 4096, 16, sha1.New)

	return key, nil
}
