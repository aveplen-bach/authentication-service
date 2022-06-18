package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"

	"github.com/aveplen-bach/authentication-service/internal/config"
	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/aveplen-bach/authentication-service/internal/model"
)

type TokenService struct {
	ss  *SessionService
	cfg config.Config
}

func NewTokenService(cfg config.Config, ss *SessionService) *TokenService {
	return &TokenService{
		ss:  ss,
		cfg: cfg,
	}
}

func (t *TokenService) NextToken(prev string) (string, error) {
	protected, err := unpack(prev)
	if err != nil {
		return "", fmt.Errorf("could not unpack prev: %w", err)
	}

	s, err := t.ss.Get(uint(protected.Payload.UserID))
	if err != nil {
		return "", fmt.Errorf("could not get session: %w", err)
	}

	unpacked, err := unpack(prev)
	if err != nil {
		return "", fmt.Errorf("could not unpack prev token: %w", err)
	}

	unprot, err := unprotect(unpacked, s.Key, s.IV)
	if err != nil {
		return "", fmt.Errorf("could not unprotect prev token: %w", err)
	}

	if s.Token.Syn.Syn+s.Token.Syn.Inc != unprot.Syn.Syn {
		return "", fmt.Errorf("provided syn is not correct")
	}

	s.Token.Syn.Syn = unprot.Syn.Syn + unprot.Syn.Inc
	s.Token.Syn.Inc = rand.Intn(1000)

	signval, err := valSign(
		unprot.Sign,
		[]byte(t.cfg.SJWTConfig.Secret),
		unprot.Header,
		unpacked.Payload,
	)
	if err != nil {
		return "", fmt.Errorf("could not validate signature: %w", err)
	}
	if !signval {
		return "", fmt.Errorf("sign of prev token is not correct")
	}

	reprotected, err := protect(s.Token, s.Key, s.IV)
	if err != nil {
		return "", fmt.Errorf("could not protect session token: %w", err)
	}

	repacked, err := pack(reprotected)
	if err != nil {
		return "", fmt.Errorf("could not pack protected: %w", err)
	}

	return repacked, nil
}

func (t *TokenService) NextSyn(userID uint, prev []byte) ([]byte, error) {
	s, err := t.ss.Get(userID)
	if err != nil {
		return nil, fmt.Errorf("could not get session: %w", err)
	}

	synb, err := cryptoutil.DecryptAesCbc(prev, s.Key, s.IV)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt prev: %w", err)
	}

	var syn model.Syn
	if err := json.Unmarshal(synb, &syn); err != nil {
		return nil, fmt.Errorf("could not unmarshal syn: %w", err)
	}

	if s.Token.Syn.Syn+s.Token.Syn.Inc != syn.Syn {
		return nil, fmt.Errorf("provided syn is not correct")
	}

	s.Token.Syn.Syn = syn.Syn + syn.Inc
	s.Token.Syn.Inc = rand.Intn(1000)

	synb, err = json.Marshal(s.Token.Syn)
	if err != nil {
		return nil, fmt.Errorf("could not marshal syn: %w", err)
	}

	encsyn, err := cryptoutil.EncryptAesCbc(synb, s.Key, s.IV)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt synb: %w", err)
	}

	return encsyn, nil
}

func (t *TokenService) Construct(userID uint, admin bool) (string, error) {
	s, err := t.ss.Get(userID)
	if err != nil {
		return "", fmt.Errorf("could not get session: %w", err)
	}

	s.Token, err = construct(userID, admin, []byte(t.cfg.SJWTConfig.Secret))
	if err != nil {
		return "", fmt.Errorf("could not construct token: %w", err)
	}

	protected, err := protect(s.Token, s.Key, s.IV)
	if err != nil {
		return "", fmt.Errorf("could not protect token: %w", err)
	}

	packed, err := pack(protected)
	if err != nil {
		return "", fmt.Errorf("could not pack token: %w", err)
	}

	return packed, nil
}

func pack(protected model.TokenProtected) (string, error) {
	headb, err := json.Marshal(protected.Header)
	if err != nil {
		return "", fmt.Errorf("could not marshal header: %w", err)
	}

	pldb, err := json.Marshal(protected.Payload)
	if err != nil {
		return "", fmt.Errorf("could not marshal payload: %w", err)
	}

	return strings.Join(b64EncodeSlice([][]byte{
		protected.SynBytes,
		headb,
		pldb,
		protected.SignBytes,
	}), "."), nil
}

func unpack(token string) (model.TokenProtected, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return model.TokenProtected{}, fmt.Errorf("token schema violated")
	}

	decoded, err := b64DecodeSlice(parts)
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not decode: %w", err)
	}

	res := model.TokenProtected{
		SynBytes:  decoded[0],
		SignBytes: decoded[3],
	}

	if err := json.Unmarshal(decoded[1], &res.Header); err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not unmarshal header: %w", err)
	}

	if err := json.Unmarshal(decoded[2], &res.Payload); err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not decode payload: %w", err)
	}

	return res, nil
}

func unprotect(protected model.TokenProtected, key, iv []byte) (model.TokenRaw, error) {
	rawSynBytes, err := cryptoutil.DecryptAesCbc(protected.SynBytes, key, iv)
	if err != nil {
		return model.TokenRaw{}, fmt.Errorf("could not decrypt syn: %w", err)
	}

	var rawSyn model.Syn
	if err := json.Unmarshal(rawSynBytes, &rawSyn); err != nil {
		return model.TokenRaw{}, fmt.Errorf("could not unmarshal syn: %w", err)
	}

	return model.TokenRaw{
		Syn:    rawSyn,
		Header: protected.Header,
		Pld:    protected.Payload,
		Sign:   protected.SignBytes,
	}, nil
}

func protect(raw model.TokenRaw, key, iv []byte) (model.TokenProtected, error) {
	synb, err := json.Marshal(raw.Syn)
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not marshal syn: %w", err)
	}

	encsyn, err := cryptoutil.EncryptAesCbc(synb, key, iv)
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not encrypt syn: %w", err)
	}

	return model.TokenProtected{
		SynBytes:  encsyn,
		Header:    raw.Header,
		Payload:   raw.Pld,
		SignBytes: raw.Sign,
	}, nil
}

func construct(userID uint, admin bool, secret []byte) (model.TokenRaw, error) {
	syn := model.Syn{
		Syn: rand.Intn(1000),
		Inc: rand.Intn(1000),
	}
	head := model.Header{
		SignAlg: "HMACSHA256",
		EncAlg:  "AESCBC",
	}
	pld := model.Payload{
		UserID: int(userID),
		Admin:  admin,
	}
	sign, err := sign(secret, head, pld)
	if err != nil {
		return model.TokenRaw{}, fmt.Errorf("could not construct token: %w", err)
	}

	return model.TokenRaw{
		Syn:    syn,
		Header: head,
		Pld:    pld,
		Sign:   sign,
	}, nil
}

func sign(secret []byte, header model.Header, payload model.Payload) ([]byte, error) {
	headb, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("could not marshal header: %w", err)
	}

	pldb, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("could not marshal payload: %w", err)
	}

	h := hmac.New(sha256.New, secret)

	data := strings.Join(b64EncodeSlice([][]byte{headb, pldb}), ".")
	if _, err := h.Write([]byte(data)); err != nil {
		return nil, fmt.Errorf("could not create sign: %w", err)
	}

	return h.Sum(nil), nil
}

func valSign(signature []byte, secret []byte, header model.Header, payload model.Payload) (bool, error) {
	headb, err := json.Marshal(header)
	if err != nil {
		return false, fmt.Errorf("could not marshal header: %w", err)
	}

	pldb, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("could not marshal payload: %w", err)
	}

	h := hmac.New(sha256.New, secret)

	data := strings.Join(b64EncodeSlice([][]byte{headb, pldb}), ".")
	if _, err := h.Write([]byte(data)); err != nil {
		return false, fmt.Errorf("could not construct hmac of original values: %w", err)
	}

	return hmac.Equal(signature, h.Sum(nil)), nil
}

func b64EncodeSlice(bytes [][]byte) []string {
	res := make([]string, len(bytes))
	for i := range bytes {
		res[i] = base64.StdEncoding.EncodeToString(bytes[i])
	}
	return res
}

func b64DecodeSlice(strs []string) ([][]byte, error) {
	res := make([][]byte, len(strs))
	var err error
	for i := range strs {
		res[i], err = base64.StdEncoding.DecodeString(strs[i])
		if err != nil {
			return nil, fmt.Errorf("decoding error: %w", err)
		}
	}
	return res, nil
}
