package model

type TokenProtected struct {
	SynBytes  []byte
	Header    Header
	Payload   Payload
	SignBytes []byte
}

type Header struct {
	SignAlg string `json:"alg"`
	EncAlg  string `json:"enc"`
}

type Payload struct {
	UserID int  `json:"userId"`
	Admin  bool `json:"admin"`
}

type TokenRaw struct {
	Syn    Syn
	Header Header
	Pld    Payload
	Sign   []byte
}

type Syn struct {
	Syn int `json:"syn"`
	Inc int `json:"inc"`
}
