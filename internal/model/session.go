package model

type SessionEntry struct {
	LoginMAC   string
	SessionKey []byte
	IV         []byte
}
