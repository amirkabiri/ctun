package socks

import (
	"context"
	"ctun/internal/client"
)

type Handler struct {
	client *client.Client
	ctx    context.Context
}
