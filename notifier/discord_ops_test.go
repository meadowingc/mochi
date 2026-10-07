package notifier

import (
	"testing"
	"time"
)

func TestDiscordRESTClientHasFiniteTimeout(t *testing.T) {
	t.Setenv("DISCORD_NOTIFIER_TOKEN", "fixture-token")
	session := getDiscordBotHandle()
	if session.Client.Timeout != 30*time.Second {
		t.Fatalf("Discord request timeout = %s", session.Client.Timeout)
	}
}
