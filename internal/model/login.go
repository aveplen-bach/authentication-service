package model

type LoginRequest struct {
	// must be present at all client messages
	Stage int `json:"stage"`

	// must be present in first client message (client conn init stage)
	Username string `json:"username"`

	// must be present in second client message (client cridentials stage)
	UserID         int    `json:"userId"`
	EncryptedPhoto string `json:"cipher"`
	IV             string `json:"iv"`
}

type LoginResponse struct {
	// must be present at all server messages
	Stage int `json:"stage"`

	// must be present at first server message (server gen mac stage)
	UserID   int    `json:"userId"`
	LoginMAC string `json:"loginMac"`

	// must be present at second serve message (server token stage)
	Token string `json:"token"`
}
