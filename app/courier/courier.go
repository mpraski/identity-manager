package courier

import "context"

type (
	Courier interface {
		Deliver(context.Context, Message) error
	}

	Message struct {
		TemplateID string
		Recipient  string
		Variables  map[string]string
	}

	Variables map[string]string
)

func NewMessage(templateID, recipient string, variables map[string]string) Message {
	return Message{
		TemplateID: templateID,
		Recipient:  recipient,
		Variables:  variables,
	}
}
