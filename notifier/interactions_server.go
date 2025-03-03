package notifier

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/bwmarrin/discordgo"
	"github.com/go-chi/chi/v5"
)

func RegisterInteractionHandlers(chiRouter *chi.Mux) {
	chiRouter.Post("/api/discord/interactions/notify", interactionHandler)
}

func interactionHandler(w http.ResponseWriter, r *http.Request) {
	// Verify the interaction request
	publicKeyStr := os.Getenv("DISCORD_NOTIFIER_PUBLIC_KEY")
	publicKeyBytes, err := hex.DecodeString(publicKeyStr)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	verified := discordgo.VerifyInteraction(r, ed25519.PublicKey(publicKeyBytes))
	if !verified {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var interaction discordgo.Interaction
	err = json.NewDecoder(r.Body).Decode(&interaction)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	switch interaction.Type {
	case discordgo.InteractionPing:
		// Respond to PING request with a PONG payload
		response := discordgo.InteractionResponse{
			Type: discordgo.InteractionResponsePong,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	case discordgo.InteractionMessageComponent:
		handleMessageComponent(interaction)
	case discordgo.InteractionApplicationCommand:
		handleApplicationCommand(interaction)
	default:
		log.Printf("Unknown interaction type: %v", interaction.Type)
		http.Error(w, "Unknown interaction type", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func handleMessageComponent(interaction discordgo.Interaction) {
	// Handle message component interactions (e.g., button clicks)
	fmt.Printf("Received message component interaction: %+v\n", interaction)
}

func handleApplicationCommand(interaction discordgo.Interaction) {
	// Handle application command interactions (e.g., slash commands)
	fmt.Printf("Received application command interaction: %+v\n", interaction)
}
