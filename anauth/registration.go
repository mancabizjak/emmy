package anauth

import (
	"github.com/go-redis/redis"
)

// SessManager checks for the presence of a registration key,
// removing it in case it exists.
// The bolean return argument indicates success (registration key
// present and subsequently deleted) or failure (absence of registration
// key).
type RegManager interface {
	CheckRegistrationKey(string) (bool, error)
}

type RedisClient struct {
	*redis.Client
}

func NewRedisClient(c *redis.Client) *RedisClient {
	return &RedisClient{
		Client: c,
	}
}

// CheckRegistrationKey checks whether provided key is present in registration database and deletes it,
// preventing another registration with the same key.
// Returns true if key was present (registration allowed), false otherwise.
func (c *RedisClient) CheckRegistrationKey(key string) (bool, error) {
	resp := c.Del(key)

	err := resp.Err()

	if err != nil {
		return false, err
	}

	return resp.Val() == 1, nil // one deleted entry indicates that the key was present in the DB
}
