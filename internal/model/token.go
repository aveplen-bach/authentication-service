package model

type TokenProtected struct {
	SynchronizationBytes []byte
	Header               Header
	Payload              Payload
	SignatureBytes       []byte
}

type Header struct {
	SignatureAlg  string `json:"alg"`
	EncryptionAlg string `json:"enc"`
}

type Payload struct {
	UserID int `json:"userId"`
}

type TokenRaw struct {
	Synchronization Synchronization
	Header          Header
	Payload         Payload
	SignatureBytes  []byte
}

type Synchronization struct {
	Syn int `json:"syn"`
	Inc int `json:"inc"`
}
