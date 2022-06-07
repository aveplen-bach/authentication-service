package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/sirupsen/logrus"
)

type TokenService struct {
	ss *SessionService
}

func NewTokenService(ss *SessionService) *TokenService {
	return &TokenService{
		ss: ss,
	}
}

func (t *TokenService) GenerateToken(userID uint) (string, error) {
	raw, err := construct(userID)
	if err != nil {
		return "", fmt.Errorf("could not construct token: %w", err)
	}

	s, err := t.ss.Get(userID)
	if err != nil {
		return "", fmt.Errorf("could not get session: %w", err)
	}

	protected, err := protect(raw, s.SessionKey, s.IV)
	if err != nil {
		return "", fmt.Errorf("could not protect token: %w", err)
	}

	packed, err := pack(protected)
	if err != nil {
		return "", fmt.Errorf("could not pack token: %w", err)
	}

	return packed, nil
}

func (t *TokenService) NextToken(token string) (string, error) {
	protected, err := unpack(token)
	if err != nil {
		return "", fmt.Errorf("could not unpack token: %w", err)
	}

	s, err := t.ss.Get(uint(protected.Payload.UserID))
	if err != nil {
		return "", fmt.Errorf("could not get session: %w", err)
	}

	raw, err := unprotect(protected, s.SessionKey, s.IV)
	if err != nil {
		return "", fmt.Errorf("could not unprotect token: %w", err)
	}

	raw.Synchronization.Syn += raw.Synchronization.Inc

	reprotected, err := protect(raw, s.SessionKey, s.IV)
	if err != nil {
		return "", fmt.Errorf("could not reprotect token: %w", err)
	}

	repacked, err := pack(reprotected)
	if err != nil {
		return "", fmt.Errorf("could not pack token: %w", err)
	}

	logrus.Info("setting new current token for %d", protected.Payload.UserID)
	s.Current = repacked

	return repacked, nil
}

func (t *TokenService) NextSyn(userID uint, protected []byte) ([]byte, error) {
	s, err := t.ss.Get(userID)
	if err != nil {
		return nil, fmt.Errorf("could not get session: %w", err)
	}

	raw, err := cryptoutil.DecryptAesCbc(protected, s.SessionKey, s.IV)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt syn: %w", err)
	}

	var syn model.Synchronization
	if err := json.Unmarshal(raw, &syn); err != nil {
		return nil, fmt.Errorf("could not unmarshal syn: %w", err)
	}

	syn.Syn += syn.Inc

	updatedRaw, err := json.Marshal(syn)
	if err != nil {
		return nil, fmt.Errorf("could not marshal syn: %w", err)
	}

	updatedProtected, err := cryptoutil.EncryptAesCbc(updatedRaw, s.SessionKey, s.IV)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt syn: %w", err)
	}

	cur, err := unpack(s.Current)
	if err != nil {
		return nil, fmt.Errorf("could not unpack current: %w", err)
	}

	unprot, err := unprotect(cur, s.SessionKey, s.IV)
	if err != nil {
		return nil, fmt.Errorf("could not unprotect current: %w", err)
	}

	unprot.Synchronization = syn

	prot, err := protect(unprot, s.SessionKey, s.IV)
	if err != nil {
		return nil, fmt.Errorf("could not reprotect current: %w", err)
	}

	repacked, err := pack(prot)
	if err != nil {
		return nil, fmt.Errorf("could not repack current: %w", err)
	}

	s.Current = repacked

	return updatedProtected, nil
}

func (t *TokenService) ValidateToken(token string) (bool, error) {
	protected, err := unpack(token)
	if err != nil {
		return false, fmt.Errorf("could not unpack token: %w", err)
	}

	session, err := t.ss.Get(uint(protected.Payload.UserID))
	if err != nil {
		return false, fmt.Errorf("could not get session: %w", err)
	}

	unprotected, err := unprotect(protected, session.SessionKey, session.IV)
	if err != nil {
		return false, fmt.Errorf("could not unprotect token: %w", err)
	}

	curprot, err := unpack(session.Current)
	if err != nil {
		return false, fmt.Errorf("could not unpack current token: %w", err)
	}

	curunprot, err := unprotect(curprot, session.SessionKey, session.IV)
	if err != nil {
		return false, fmt.Errorf("could not unprotect current token: %w", err)
	}

	if unprotected.Synchronization.Syn+unprotected.Synchronization.Inc != curunprot.Synchronization.Syn {
		return false, fmt.Errorf("syn is invalid")
	}

	headb, err := json.Marshal(protected.Header)
	if err != nil {
		return false, fmt.Errorf("could not marshal header: %w", err)
	}

	pldb, err := json.Marshal(protected.Payload)
	if err != nil {
		return false, fmt.Errorf("could not marshal payload: %w", err)
	}

	secret := "mysecret"
	data := fmt.Sprintf(
		"%s.%s",
		base64.StdEncoding.EncodeToString(headb),
		base64.StdEncoding.EncodeToString(pldb))

	h := hmac.New(sha256.New, []byte(secret))
	if _, err := h.Write([]byte(data)); err != nil {
		return false, fmt.Errorf("could not create sign: %w", err)
	}

	return hmac.Equal(protected.SignatureBytes, h.Sum(nil)), nil
}

func (t *TokenService) ValidateSyn(userID uint, protected []byte) (bool, error) {
	session, err := t.ss.Get(uint(userID))
	if err != nil {
		return false, fmt.Errorf("could not get session: %w", err)
	}

	raw, err := cryptoutil.DecryptAesCbc(protected, session.SessionKey, session.IV)
	if err != nil {
		return false, fmt.Errorf("could not decrypt syn: %w", err)
	}

	var syn model.Synchronization
	if err := json.Unmarshal(raw, &syn); err != nil {
		return false, fmt.Errorf("could not unmarshal syn: %w", err)
	}

	curprot, err := unpack(session.Current)
	if err != nil {
		return false, fmt.Errorf("could not unpack current token: %w", err)
	}

	curunprot, err := unprotect(curprot, session.SessionKey, session.IV)
	if err != nil {
		return false, fmt.Errorf("could not unprotect current token: %w", err)
	}

	if syn.Syn+syn.Inc != curunprot.Synchronization.Syn {
		return false, fmt.Errorf("syn is invalid")
	}

	return true, nil
}

func (t *TokenService) ExtractPayload(token string) (model.Payload, error) {
	protected, err := unpack(token)
	if err != nil {
		return model.Payload{}, fmt.Errorf("could not deconstruct token: %w", err)
	}

	return protected.Payload, nil
}

func protect(raw model.TokenRaw, key, iv []byte) (model.TokenProtected, error) {
	synb, err := json.Marshal(raw.Synchronization)
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not marshal syn: %w", err)
	}

	encsyn, err := cryptoutil.EncryptAesCbc(synb, key, iv)
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not encrypt syn: %w", err)
	}

	return model.TokenProtected{
		SynchronizationBytes: encsyn,
		Header:               raw.Header,
		Payload:              raw.Payload,
		SignatureBytes:       raw.SignatureBytes,
	}, nil
}

func unprotect(protected model.TokenProtected, key, iv []byte) (model.TokenRaw, error) {
	rawSynBytes, err := cryptoutil.DecryptAesCbc(protected.SynchronizationBytes, key, iv)
	if err != nil {
		return model.TokenRaw{}, fmt.Errorf("could not decrypt syn: %w", err)
	}

	var rawSyn model.Synchronization
	if err := json.Unmarshal(rawSynBytes, &rawSyn); err != nil {
		return model.TokenRaw{}, fmt.Errorf("could not unmarshal syn: %w", err)
	}

	return model.TokenRaw{
		Synchronization: rawSyn,
		Header:          protected.Header,
		Payload:         protected.Payload,
		SignatureBytes:  protected.SignatureBytes,
	}, nil
}

func pack(protected model.TokenProtected) (string, error) {
	b64Syn := base64.StdEncoding.EncodeToString(protected.SynchronizationBytes)

	headBytes, err := json.Marshal(protected.Header)
	if err != nil {
		return "", fmt.Errorf("could not marshal header part: %w", err)
	}
	b64Head := base64.StdEncoding.EncodeToString(headBytes)

	pldBytes, err := json.Marshal(protected.Payload)
	if err != nil {
		return "", fmt.Errorf("could not marshal payload part: %w", err)
	}
	b64Pld := base64.StdEncoding.EncodeToString(pldBytes)

	b64Sig := base64.StdEncoding.EncodeToString(protected.SignatureBytes)

	return fmt.Sprintf(
		"%s.%s.%s.%s",
		b64Syn,
		b64Head,
		b64Pld,
		b64Sig,
	), nil
}

func unpack(token string) (model.TokenProtected, error) {
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 4 {
		return model.TokenProtected{}, fmt.Errorf("token is damaged or of wrong format")
	}

	syn, err := base64.StdEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not decode syn: %w", err)
	}

	headb, err := base64.StdEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not decode header: %w", err)
	}

	var head model.Header
	if err := json.Unmarshal(headb, &head); err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not unmarshal header: %w", err)
	}

	pldb, err := base64.StdEncoding.DecodeString(tokenParts[2])
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not decode payload: %w", err)
	}
	var payload model.Payload
	if err := json.Unmarshal(pldb, &payload); err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not unmarshal payload: %w", err)
	}

	sign, err := base64.StdEncoding.DecodeString(tokenParts[3])
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not decode sign: %w", err)
	}

	return model.TokenProtected{
		SynchronizationBytes: syn,
		Header:               head,
		Payload:              payload,
		SignatureBytes:       sign,
	}, nil
}

func construct(userID uint) (model.TokenRaw, error) {
	syn := constructSynchronization()
	head := constructHead()
	pld := constructPayload(userID)
	sign, err := constructSignature(head, pld)
	if err != nil {
		return model.TokenRaw{}, fmt.Errorf("could not construct token: %w", err)
	}

	return model.TokenRaw{
		Synchronization: syn,
		Header:          head,
		Payload:         pld,
		SignatureBytes:  sign,
	}, nil
}

func constructSynchronization() model.Synchronization {
	return model.Synchronization{
		Syn: rand.Intn(10000),
		Inc: rand.Intn(10000),
	}
}

func constructHead() model.Header {
	return model.Header{
		SignatureAlg:  "HMACSHA256",
		EncryptionAlg: "AESCBC",
	}
}

func constructPayload(userID uint) model.Payload {
	return model.Payload{
		UserID: int(userID),
		Admin:  true,
	}
}

func constructSignature(header model.Header, payload model.Payload) ([]byte, error) {
	headb, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("could not marshal header: %w", err)
	}

	pldb, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("could not marshal payload: %w", err)
	}

	secret := "mysecret"
	data := fmt.Sprintf(
		"%s.%s",
		base64.StdEncoding.EncodeToString(headb),
		base64.StdEncoding.EncodeToString(pldb))

	h := hmac.New(sha256.New, []byte(secret))
	if _, err := h.Write([]byte(data)); err != nil {
		return nil, fmt.Errorf("could not create sign: %w", err)
	}

	return h.Sum(nil), nil
}

func validateSynchronization(cur, next model.Synchronization) bool {
	return cur.Syn+cur.Inc == next.Syn
}

func validateSignature(signature []byte, header model.Header, payload model.Payload) (bool, error) {
	headb, err := json.Marshal(header)
	if err != nil {
		return false, fmt.Errorf("could not marshal header: %w", err)
	}

	pldb, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("could not marshal payload: %w", err)
	}

	secret := "mysecret"
	data := fmt.Sprintf(
		"%s.%s",
		base64.StdEncoding.EncodeToString(headb),
		base64.StdEncoding.EncodeToString(pldb))

	h := hmac.New(sha256.New, []byte(secret))
	if _, err := h.Write([]byte(data)); err != nil {
		return false, fmt.Errorf("could not create sign: %w", err)
	}

	return hmac.Equal(signature, h.Sum(nil)), nil
}
