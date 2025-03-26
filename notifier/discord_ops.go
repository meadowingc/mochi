package notifier

import (
	"fmt"
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

func SendMessageToUsername(username string, message string) error {
	// First check if the user has discord notifications enabled
	settings, err := GetDiscordSettingsByUsername(username)
	if err != nil {
		return fmt.Errorf("error getting discord settings: %v", err)
	}

	if !settings.DiscordVerified || !settings.NotificationsEnabled || settings.DiscordUsername == "" {
		return fmt.Errorf("user has not enabled discord notifications")
	}

	discord := getDiscordBotHandle()

	// Search for the user in the guild
	// bot needs to be in the guild first
	members, err := discord.GuildMembersSearch(os.Getenv("DISCORD_NOTIFIER_GUILD_ID"), settings.DiscordUsername, 1)
	if err != nil {
		return fmt.Errorf("error searching for user: %v", err)
	}

	if len(members) == 0 {
		return fmt.Errorf("user not found in guild")
	}

	userID := members[0].User.ID

	// Create a DM channel with the user
	channel, err := discord.UserChannelCreate(userID)
	if err != nil {
		return fmt.Errorf("error creating DM channel: %v", err)
	}

	// Send a message to the DM channel
	_, err = discord.ChannelMessageSend(channel.ID, message)
	if err != nil {
		return fmt.Errorf("error sending message: %v", err)
	}

	return nil
}
