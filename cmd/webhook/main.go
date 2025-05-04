package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type WebhookInfo struct {
	UserID string `json:"user_id"`
	OldIP  string `json:"old_ip"`
	NewIP  string `json:"new_ip"`
}

func main() {
	http.HandleFunc("POST /webhook", func(w http.ResponseWriter, r *http.Request) {
		webhookInfo := &WebhookInfo{}
		if err := json.NewDecoder(r.Body).Decode(webhookInfo); err != nil {
			log.Println("failed to decode webhook info", err)
			http.Error(w, "failed to decode webhook info", http.StatusBadRequest)
			return
		}
		defer r.Body.Close() // nolint
		log.Printf("Received webhook: UserID: %s, OldIP: %s, NewIP: %s\n", webhookInfo.UserID, webhookInfo.OldIP, webhookInfo.NewIP)
	})
	log.Fatal(http.ListenAndServe(":9091", nil))
}
