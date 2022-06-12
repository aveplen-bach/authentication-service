package model

type SessionEntry struct {
	LoginMAC string
	Key      []byte
	IV       []byte
	Token    TokenRaw
}
