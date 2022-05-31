package model

type LoginRequest struct {
	Stage          int    `json:"stage"`
	SessionID      int    `json:"sessionId"`
	Username       string `json:"username"`
	EncryptedPhoto string `json:"cipher"`
	IV             string `json:"iv"`
}

type LoginResponse struct {
	Stage     int    `json:"stage"`
	SessionID int    `json:"sessionId"`
	MAC       string `json:"mac"`
	JWT       string `json:"token"`
}
