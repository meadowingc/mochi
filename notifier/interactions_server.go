package notifier

import (
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/bwmarrin/discordgo"
)

func StartInteractionHandler() {
	session := getDiscordBotHandle()

	session.AddHandler(func(s *discordgo.Session, r *discordgo.Ready) {
		log.Printf("Logged in as %s", r.User.String())
	})

	session.AddHandler(func(s *discordgo.Session, r *discordgo.MessageCreate) {
		// Ignore messages from the bot itself
		if r.Author.ID == s.State.User.ID {
			return
		}

		// Check if this is a DM
		channel, err := s.Channel(r.ChannelID)
		if err != nil {
			log.Printf("Error getting channel: %v", err)
			return
		}

		// Only process DMs
		if channel.Type != discordgo.ChannelTypeDM {
			return
		}

		log.Printf("DM from %s: %s", r.Author.Username, r.Content)

		// Check if message looks like a verification code (trim whitespace)
		code := strings.TrimSpace(r.Content)
		if len(code) >= 6 && len(code) <= 12 {
			// Try to find a user with this verification code
			settings, err := FindUserByDiscordVerifyCode(code)
			if err != nil {
				// Send error message to the user
				s.ChannelMessageSend(r.ChannelID, "Sorry, that verification code is invalid or has expired. Please generate a new code from your Mochi settings page.")
				return
			}

			// Update the user's Discord information
			settings.DiscordUsername = r.Author.Username
			settings.DiscordVerified = true
			settings.DiscordVerifyCode = ""      // Clear the code
			settings.NotificationsEnabled = true // Enable by default

			err = UpdateDiscordSettings(settings)
			if err != nil {
				log.Printf("Error updating user: %v", err)
				s.ChannelMessageSend(r.ChannelID, "There was an error verifying your account. Please try again later.")
				return
			}

			// Send success message
			s.ChannelMessageSend(r.ChannelID, "Success! Your Discord account is now connected to your Mochi account. You will now receive notifications here when important events occur.")
		} else {
			// Not a verification code, send help message
			s.ChannelMessageSend(r.ChannelID, "Hello! I'm the Mochi notification bot. If you're trying to verify your Mochi account, please send the verification code shown on your settings page.")
		}
	})

	err := session.Open()
	if err != nil {
		log.Fatalf("could not open session: %s", err)
	}

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)
	<-sigch

	err = session.Close()
	if err != nil {
		log.Printf("could not close session gracefully: %s", err)
	}
}
