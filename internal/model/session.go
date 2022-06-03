package model

type SessionEntry struct {
	MessageAuthCode string
	SessionKey      []byte
	IV              []byte
	UserID          int
	UserIDSet       bool
}
