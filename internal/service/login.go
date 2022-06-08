package service

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/util"
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

func (ls *LoginService) handleConnectionInit(lreq *model.LoginRequest) (*model.LoginResponse, error) {
	user, err := ls.us.GetUserByUsername(lreq.Username)
	if err != nil {
		return nil, fmt.Errorf("could not find user with given username: %w", err)
	}

	lmac, err := cryptoutil.GenerateRandomString(LoginMACLength)
	if err != nil {
		return nil, err
	}

	session, err := ls.session.New(user.ID)
	if err != nil {
		return nil, fmt.Errorf("could not initialize session: %w", err)
	}
	session.LoginMAC = lmac

	return &model.LoginResponse{
		Stage:    STAGE_SERVER_GEN_MAC,
		LoginMAC: lmac,
	}, nil
}

// client cridentials stage

func (ls *LoginService) handleCredentials(lreq *model.LoginRequest) (*model.LoginResponse, error) {
	user, err := ls.us.GetUserByUsername(lreq.Username)
	if err != nil {
		return nil, fmt.Errorf("could not find user with given username: %w", err)
	}

	// get users session
	session, err := ls.session.Get(user.ID)
	if err != nil {
		return nil, fmt.Errorf("could not get user session: %w", err)
	}

	// derive session key
	skey, err := deriveSessionKey([]byte(user.Password), session.LoginMAC)
	if err != nil {
		return nil, err
	}

	// save session key
	session.SessionKey = skey

	if lreq.EncryptedPhoto == nil {
		return nil, fmt.Errorf("photo cipher is not present")
	}

	// decrypt photo
	photoCipher, err := base64.StdEncoding.DecodeString(*lreq.EncryptedPhoto)
	if err != nil {
		return nil, err
	}

	if lreq.IV == nil {
		return nil, fmt.Errorf("iv cipher is not present")
	}

	iv, err := base64.StdEncoding.DecodeString(*lreq.IV)
	if err != nil {
		return nil, err
	}
	session.IV = iv

	photo, err := cryptoutil.DecryptAesCbc(photoCipher, skey, iv)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt photo: %w", err)
	}

	// check photo
	photoVector, err := ls.ps.ExtractVector(photo)
	if err != nil {
		return nil, fmt.Errorf("could not extract vector: %w", err)
	}

	photoIsCloseEnough, err := ls.ps.PhotoIsCloseEnough(util.DeserializeFloats64(user.FFVector), photoVector)
	if err != nil {
		return nil, fmt.Errorf("cannot get distance between photots: %w", err)
	}

	if !photoIsCloseEnough {
		return nil, fmt.Errorf("photo is not close enough")
	}

	// generate token
	token, err := ls.token.GenerateToken(user.ID, user.Admin)
	if err != nil {
		return nil, err
	}

	return &model.LoginResponse{
		Stage: STAGE_SERVER_TOKEN,
		Token: token,
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
