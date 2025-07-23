package shieldsender

import "context"

// MessageKey is a unique identifier of a sent message used
// for discriminating the message.
type MessageKey string

const (
	// shieldpasswordreset.
	MessageKeyPasswordResetRequest MessageKey = "message_key_password_reset_request"
	MessageKeyPasswordResetSuccess MessageKey = "message_key_password_reset_success"

	// shieldpassword.
	MessageKeyPasswordChange MessageKey = "message_key_password_change"

	// shielduser.
	MessageKeyEmailChange MessageKey = "message_key_email_change"
)

// Message is a message to be sent.
type Message struct {
	Payload any
	Email   string
	Key     MessageKey
}

// Sender is an interface for sending email messages.
type Sender interface {
	// Send sends the given message.
	Send(context.Context, Message) error
}
