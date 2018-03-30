package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConnectionTimeout tests whether timeout of initial connection to the server is reached.
func TestConnectionTimeout(t *testing.T) {
	_, err := GetConnection(NewConnectionConfig("localhost:4321", "",
		nil, 100))
	assert.NotNil(t, err, "there is no emmy server listening on a given address, "+
		"timeout should be reached")
}
