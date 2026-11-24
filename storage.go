package osin

import (
	"errors"
)

var (
	// ErrNotFound is the error returned by Storage Get<...> and Load<...> functions in case
	// no entity is found in the storage. E.g. Storage.GetClient() returns ErrNotFound when
	// client is not found. All other returned errors must be treated as storage-specific errors,
	// like "connection lost", "connection refused", etc.
	ErrNotFound = errors.New("Entity not found")

	// ErrRefreshTokenRotated is the error returned by Storage RotateRefresh when the
	// refresh token has already been rotated (or its rotation sequence does not match),
	// meaning the token was replayed or concurrently refreshed.
	ErrRefreshTokenRotated = errors.New("Refresh token already rotated")
)

// Storage interface
type Storage interface {
	// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
	// to avoid concurrent access problems.
	// This is to avoid cloning the connection at each method access.
	// Can return itself if not a problem.
	Clone() Storage

	// Close the resources the Storage potentially holds (using Clone for example)
	Close()

	// GetClient loads the client by id (client_id)
	GetClient(id string) (Client, error)

	// SaveAuthorize saves authorize data.
	SaveAuthorize(*AuthorizeData) error

	// LoadAuthorize looks up AuthorizeData by a code.
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorize(code string) (*AuthorizeData, error)

	// RemoveAuthorize revokes or deletes the authorization code.
	RemoveAuthorize(code string) error

	// SaveAccess writes AccessData.
	// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
	SaveAccess(*AccessData) error

	// LoadAccess retrieves access data by token. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadAccess(token string) (*AccessData, error)

	// RemoveAccess revokes or deletes an AccessData.
	RemoveAccess(token string) error

	// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadRefresh(token string) (*AccessData, error)

	// RemoveRefresh revokes or deletes refresh AccessData.
	RemoveRefresh(token string) error

	// RotateRefresh atomically marks the refresh token as rotated, but only if its
	// current rotation sequence still equals sequence. It must return
	// ErrRefreshTokenRotated if the token was already rotated or the sequence does
	// not match, so that concurrent refreshes of the same token cannot both succeed.
	RotateRefresh(token string, sequence int64) error

	// RemoveRefreshFamily revokes or deletes all access and refresh tokens
	// belonging to the given refresh token family.
	RemoveRefreshFamily(family string) error
}
