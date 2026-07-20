package store

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"eino-ops-agent/internal/domain"
)

func TestChatAttachmentsPersistForHistoryAndModelContext(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir()+"/chat-images.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	imageData := []byte("valid-image-fixture")
	messageID, err := st.AppendPendingChatMessageWithAttachments(ctx, "session-images", "user", "inspect this", []domain.ChatAttachment{{
		Name: "screen.png", MIMEType: "image/png", Data: imageData,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetChatMessageStatus(ctx, messageID, "completed"); err != nil {
		t.Fatal(err)
	}

	history, err := st.ListChatMessages(ctx, "session-images", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || len(history[0].Attachments) != 1 {
		t.Fatalf("history attachments = %#v", history)
	}
	metadata := history[0].Attachments[0]
	if metadata.Name != "screen.png" || metadata.MIMEType != "image/png" || metadata.SizeBytes != int64(len(imageData)) || len(metadata.Data) != 0 {
		t.Fatalf("public attachment metadata = %#v", metadata)
	}

	modelHistory, _, err := st.ListChatContextMessages(ctx, "session-images", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(modelHistory) != 1 || len(modelHistory[0].Attachments) != 1 || !bytes.Equal(modelHistory[0].Attachments[0].Data, imageData) {
		t.Fatalf("model attachment data = %#v", modelHistory)
	}
	loaded, err := st.GetChatAttachment(ctx, "session-images", metadata.ID)
	if err != nil || !bytes.Equal(loaded.Data, imageData) {
		t.Fatalf("loaded attachment = %#v, err = %v", loaded, err)
	}
	if _, err := st.GetChatAttachment(ctx, "another-session", metadata.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-session attachment lookup error = %v", err)
	}

	if err := st.DeleteChatSession(ctx, "session-images"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetChatAttachment(ctx, "session-images", metadata.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("attachment survived session deletion: %v", err)
	}
}
