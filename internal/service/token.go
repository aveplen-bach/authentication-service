package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"sync"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/aveplen-bach/authentication-service/internal/model"
)

type TokenService struct {
	ss *SessionService
	cs *CryptoService
}

func NewTokenService(ss *SessionService) *TokenService {
	return &TokenService{
		ss: ss,
	}
}

func (t *TokenService) GenerateAdminToken(userID uint) (string, error) {
	return t.generateToken(userID, true)
}

func (t *TokenService) GenerateUserToken(userID uint) (string, error) {
	return t.generateToken(userID, false)
}

func (t *TokenService) generateToken(userID uint, admin bool) (string, error) {

	raw, err := func() (model.TokenRaw, error) {
		if admin {
			return constructAdmin(userID)
		}
		return constructUser(userID)
	}()
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

	raw, err := t.unprotect(protected)
	if err != nil {
		return "", fmt.Errorf("could not unprotect token: %w", err)
	}

	raw = incsyn(raw)

	reprotected, err := t.protect(raw)
	if err != nil {
		return "", fmt.Errorf("could not reprotect token: %w", err)
	}

	repacked, err := pack(reprotected)
	if err != nil {
		return "", fmt.Errorf("could not pack token: %w", err)
	}

	return repacked, nil
}

func (t *TokenService) unprotect(protected model.TokenProtected) (model.TokenRaw, error) {
	s, err := t.ss.Get(uint(protected.Payload.UserID))
	if err != nil {
		return model.TokenRaw{}, fmt.Errorf("could not get session: %w", err)
	}

	return unprotect(protected, s.SessionKey, s.IV)
}

func (t *TokenService) protect(raw model.TokenRaw) (model.TokenProtected, error) {
	s, err := t.ss.Get(uint(raw.Payload.UserID))
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not get session: %w", err)
	}

	return protect(raw, s.SessionKey, s.IV)
}

func incsyn(raw model.TokenRaw) model.TokenRaw {
	raw.Synchronization.Syn += raw.Synchronization.Inc
	return raw
}

func (t *TokenService) NextSyn(userID uint, protected []byte) ([]byte, error) {
	s, err := t.ss.Get(userID)
	if err != nil {
		return nil, fmt.Errorf("could not get session: %w", err)
	}

	raw, err := t.cs.Decrypt(userID, protected)
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

	updatedProtected, err := t.cs.Encrypt(userID, updatedRaw)
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

	if len(session.Current) == 0 {
		return true, nil
	}

	curprot, err := unpack(session.Current)
	if err != nil {
		return false, fmt.Errorf("could not unpack current token: %w", err)
	}

	curunprot, err := unprotect(curprot, session.SessionKey, session.IV)
	if err != nil {
		return false, fmt.Errorf("could not unprotect current token: %w", err)
	}

	fmt.Println(curunprot)
	fmt.Println(unprotected)

	// if unprotected.Synchronization.Syn+unprotected.Synchronization.Inc != curunprot.Synchronization.Syn {
	// 	return false, fmt.Errorf("syn is invalid")
	// }

	// if curunprot.Synchronization.Syn+curunprot.Synchronization.Inc != unprotected.Synchronization.Syn {
	// 	return false, fmt.Errorf("syn is invalid")
	// }

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

	if !hmac.Equal(protected.SignatureBytes, h.Sum(nil)) {
		return false, fmt.Errorf("signature is not valid")
	}

	return true, nil
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
	res := make([]interface{}, 4)
	mu := new(sync.Mutex)
	wg := new(sync.WaitGroup)

	errch := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		mu.Lock()
		defer mu.Unlock()
		res[0] = encode(protected.SynchronizationBytes)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		mu.Lock()
		defer mu.Unlock()

		headb, err := mhead(protected.Header)
		if err != nil {
			errch <- fmt.Errorf("could not get byte representation of head: %w", err)
			return
		}

		res[1] = encode(headb)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		mu.Lock()
		defer mu.Unlock()

		pldb, err := mpld(protected.Payload)
		if err != nil {
			errch <- fmt.Errorf("could not get byte representation of payload: %w", err)
			return
		}

		res[2] = encode(pldb)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		mu.Lock()
		defer mu.Unlock()
		res[3] = encode(protected.SignatureBytes)
	}()

	wg.Wait()
	for err := range errch {
		return "", fmt.Errorf("could not get string representation of token: %w", err)
	}

	return fmt.Sprintf("%s.%s.%s.%s", res...), nil
}

func unpack(token string) (model.TokenProtected, error) {
	tparts, err := lex(token)
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not lex: %w", err)
	}

	parsed, err := parse(tparts)
	if err != nil {
		return model.TokenProtected{}, fmt.Errorf("could not parse: %w", err)
	}

	return parsed, nil
}

func constructAdmin(userID uint) (model.TokenRaw, error) {
	return construct(userID, true)
}

func constructUser(userID uint) (model.TokenRaw, error) {
	return construct(userID, false)
}

func construct(userID uint, admin bool) (model.TokenRaw, error) {
	syn := constructSynchronization()
	head := constructHead()
	var pld model.Payload
	if admin {
		pld = constructAdminPayload(userID)
	} else {
		pld = constructUserPayload(userID)
	}
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

func constructAdminPayload(userID uint) model.Payload {
	return constructPayload(userID, true)
}

func constructUserPayload(userID uint) model.Payload {
	return constructPayload(userID, false)
}

func constructPayload(userID uint, admin bool) model.Payload {
	return model.Payload{
		UserID: int(userID),
		Admin:  admin,
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

type tparts struct {
	syn  string
	head string
	pld  string
	sign string
}

func lex(token string) (tparts, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return tparts{}, fmt.Errorf("token should consist of 4 parts")
	}

	return tparts{
		syn:  parts[0],
		head: parts[1],
		pld:  parts[2],
		sign: parts[3],
	}, nil
}

func parse(tparts tparts) (model.TokenProtected, error) {
	var protected model.TokenProtected
	mu := new(sync.Mutex)
	wg := new(sync.WaitGroup)

	errch := make(chan error, 4)
	defer close(errch)

	wg.Add(1)
	go func(errch chan<- error) {
		defer wg.Done()
		synb, err := decode(tparts.syn)

		if err != nil {
			errch <- fmt.Errorf("could not construct instance of syn: %w", err)
			return
		}

		mu.Lock()
		defer mu.Unlock()
		protected.SynchronizationBytes = synb
	}(errch)

	wg.Add(1)
	go func(errch chan<- error) {
		defer wg.Done()
		head, err := phead(tparts.head)
		if err != nil {
			errch <- fmt.Errorf("could not construct instance of head: %w", err)
			return
		}

		mu.Lock()
		defer mu.Unlock()
		protected.Header = head
	}(errch)

	wg.Add(1)
	go func(errch chan<- error) {
		defer wg.Done()
		pld, err := ppld(tparts.pld)
		if err != nil {
			errch <- fmt.Errorf("could not construct instance of payload: %w", err)
			return
		}

		mu.Lock()
		defer mu.Unlock()
		protected.Payload = pld
	}(errch)

	wg.Add(1)
	go func(errch chan<- error) {
		defer wg.Done()
		signb, err := decode(tparts.sign)

		if err != nil {
			errch <- fmt.Errorf("could not construct instance of signature: %w", err)
			return
		}

		mu.Lock()
		defer mu.Unlock()
		protected.SignatureBytes = signb
	}(errch)

	wg.Wait()
	for err := range errch {
		return model.TokenProtected{}, err
	}

	return protected, nil
}

func phead(head string) (model.Header, error) {
	headb, err := decode(head)
	if err != nil {
		return model.Header{}, fmt.Errorf("could not decode head: %w", err)
	}

	headp, err := unmhead(headb)
	if err != nil {
		return model.Header{}, fmt.Errorf("could not unmarshal head: %w", err)
	}

	return headp, nil
}

func unmhead(headb []byte) (model.Header, error) {
	var headp model.Header
	if err := json.Unmarshal(headb, &headp); err != nil {
		return model.Header{}, fmt.Errorf("could not unmarshal head: %w", err)
	}
	return headp, nil
}

func ppld(pld string) (model.Payload, error) {
	pldb, err := decode(pld)
	if err != nil {
		return model.Payload{}, fmt.Errorf("could not decode payload: %w", err)
	}

	pldp, err := unmpld(pldb)
	if err != nil {
		return model.Payload{}, fmt.Errorf("could not unmarhsal payload: %w", err)
	}

	return pldp, nil
}

func unmpld(pldb []byte) (model.Payload, error) {
	var pldp model.Payload
	if err := json.Unmarshal(pldb, &pldp); err != nil {
		return model.Payload{}, fmt.Errorf("could not unmarshal payload: %w", err)
	}
	return pldp, nil
}

func decode(src string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(src)
}

func encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func mhead(head model.Header) ([]byte, error) {
	headb, err := json.Marshal(head)
	if err != nil {
		return nil, fmt.Errorf("could not marshal header: %w", err)
	}
	return headb, nil
}

func mpld(pld model.Payload) ([]byte, error) {
	headb, err := json.Marshal(pld)
	if err != nil {
		return nil, fmt.Errorf("could not marshal paylaod: %w", err)
	}
	return headb, nil
}

func validateSynchronization(cur, next model.Synchronization) bool {
	return cur.Syn+cur.Inc == next.Syn
}

func signatureIsValid(signature []byte, header model.Header, payload model.Payload) (bool, error) {
	wg := new(sync.WaitGroup)

	errch := make(chan error, 2)
	defer close(errch)

	headch := make(chan string)
	defer close(headch)

	pldch := make(chan string)
	defer close(pldch)

	wg.Add(1)
	go func(header model.Header, headch chan<- string, errch chan<- error) {
		defer wg.Done()
		haedb, err := mhead(header)
		if err != nil {
			errch <- fmt.Errorf("could not get byte representation of header: %w", err)
			return
		}
		headch <- encode(haedb)
	}(header, headch, errch)

	wg.Add(1)
	go func(pld model.Payload, pldch chan<- string, errch chan<- error) {
		defer wg.Done()
		pldb, err := mpld(payload)
		if err != nil {
			errch <- fmt.Errorf("could not get byte representation of payload: %w", err)
			return
		}
		pldch <- encode(pldb)
	}(payload, pldch, errch)

	wg.Wait()
	for err := range errch {
		return false, fmt.Errorf("could not construct hmac of original values: %w", err)
	}

	secret := "mysecret"
	data := fmt.Sprintf("%s.%s", <-headch, <-pldch)
	h := hmac.New(sha256.New, []byte(secret))
	if _, err := h.Write([]byte(data)); err != nil {
		return false, fmt.Errorf("could not construct hmac of original values: %w", err)
	}

	return hmac.Equal(signature, h.Sum(nil)), nil
}
