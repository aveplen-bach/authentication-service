package model

type RegisterRequest struct {
	EncryptedPayload string `json:"encryptedPayload"`
	IV               string `json:"iv"`
}

type RegisterRequestPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Photo    string `json:"photo"`
}
