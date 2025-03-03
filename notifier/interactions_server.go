package notifier

import (
	"log"
	"os"
	"os/signal"

	"github.com/bwmarrin/discordgo"
)

func StartInteractionHandler() {
	session := getDiscordBotHandle()

	session.AddHandler(func(s *discordgo.Session, r *discordgo.Ready) {
		log.Printf("Logged in as %s", r.User.String())
	})

	session.AddHandler(func(s *discordgo.Session, r *discordgo.MessageCreate) {
		log.Printf("Message from %s: %s", r.Author.Username, r.Content)
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
