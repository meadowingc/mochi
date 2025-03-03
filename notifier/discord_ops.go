package notifier

import (
	"log"
	"os"

	"github.com/bwmarrin/discordgo"
)

func getDiscordBotHandle() *discordgo.Session {
	discord, err := discordgo.New("Bot " + os.Getenv("DISCORD_NOTIFIER_TOKEN"))
	if err != nil {
		panic(err)
	}

	return discord
}

func SendMessageToUsername(username string, message string) {
	discord := getDiscordBotHandle()

	// Search for the user in the guild
	// bot needs to be in the guild first
	members, err := discord.GuildMembersSearch(os.Getenv("DISCORD_NOTIFIER_GUILD_ID"), username, 1)
	if err != nil {
		log.Printf("Error searching for user: %v", err)
		return
	}

	if len(members) == 0 {
		log.Printf("User not found")
		return
	}

	userID := members[0].User.ID

	// Create a DM channel with the user
	channel, err := discord.UserChannelCreate(userID)
	if err != nil {
		log.Printf("Error creating DM channel: %v", err)
		return
	}

	// Send a message to the DM channel
	_, err = discord.ChannelMessageSend(channel.ID, message)
	if err != nil {
		log.Printf("Error sending message: %v", err)
		return
	}
}
