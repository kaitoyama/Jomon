//go:build !debug

package router

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/traPtitech/Jomon/model"
)

// stubAdminRepo is a minimal AdministratorRepository for exercising the Bearer
// service-auth branch of AuthUser without a database.
type stubAdminRepo struct {
	admins []string
	err    error
}

func (r *stubAdminRepo) IsAdmin(userId string) (bool, error) {
	for _, a := range r.admins {
		if a == userId {
			return true, r.err
		}
	}
	return false, r.err
}
func (r *stubAdminRepo) GetAdministratorList() ([]string, error) { return r.admins, r.err }
func (r *stubAdminRepo) AddAdministrator(string) error           { return r.err }
func (r *stubAdminRepo) RemoveAdministrator(string) error        { return r.err }

func newAuthContext(authHeader string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/applications", nil)
	if authHeader != "" {
		req.Header.Set(echo.HeaderAuthorization, authHeader)
	}
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

// A valid Bearer service token authenticates as the configured trap_id and, when
// that trap_id is a Jomon admin, is marked admin in the request context.
func TestAuthUser_ServiceBearer_Valid(t *testing.T) {
	t.Setenv("SERVICE_TOKEN", "s3cret-token")
	t.Setenv("SERVICE_USER_TRAP_ID", "checkin")
	s := Service{Administrators: &stubAdminRepo{admins: []string{"checkin"}}}

	c, _ := newAuthContext("Bearer s3cret-token")
	got, err := s.AuthUser(c)

	assert.NoError(t, err)
	assert.NotNil(t, got)
	user, ok := got.Get(contextUserKey).(model.User)
	assert.True(t, ok)
	assert.Equal(t, "checkin", user.TrapId)
	assert.True(t, user.IsAdmin)
	assert.Equal(t, "", got.Get(contextAccessTokenKey))
}

// The service identity authenticates even when it is not (yet) an admin, but is
// not marked admin — the handler-level IsAdmin check then rejects writes.
func TestAuthUser_ServiceBearer_ValidNonAdmin(t *testing.T) {
	t.Setenv("SERVICE_TOKEN", "s3cret-token")
	t.Setenv("SERVICE_USER_TRAP_ID", "checkin")
	s := Service{Administrators: &stubAdminRepo{admins: []string{"someoneElse"}}}

	c, _ := newAuthContext("Bearer s3cret-token")
	got, err := s.AuthUser(c)

	assert.NoError(t, err)
	assert.NotNil(t, got)
	user, _ := got.Get(contextUserKey).(model.User)
	assert.Equal(t, "checkin", user.TrapId)
	assert.False(t, user.IsAdmin)
}

// A present-but-wrong Bearer token is rejected with 401 (no session fallback).
func TestAuthUser_ServiceBearer_InvalidToken(t *testing.T) {
	t.Setenv("SERVICE_TOKEN", "s3cret-token")
	t.Setenv("SERVICE_USER_TRAP_ID", "checkin")
	s := Service{Administrators: &stubAdminRepo{admins: []string{"checkin"}}}

	c, rec := newAuthContext("Bearer wrong-token")
	got, _ := s.AuthUser(c)

	assert.Nil(t, got)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// With SERVICE_TOKEN unset, any Bearer token is rejected (feature disabled).
func TestAuthUser_ServiceBearer_NotConfigured(t *testing.T) {
	t.Setenv("SERVICE_TOKEN", "")
	t.Setenv("SERVICE_USER_TRAP_ID", "checkin")
	s := Service{Administrators: &stubAdminRepo{}}

	c, rec := newAuthContext("Bearer anything")
	got, _ := s.AuthUser(c)

	assert.Nil(t, got)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// A valid token with no SERVICE_USER_TRAP_ID configured is rejected (we refuse
// to act as an empty identity).
func TestAuthUser_ServiceBearer_MissingTrapId(t *testing.T) {
	t.Setenv("SERVICE_TOKEN", "s3cret-token")
	t.Setenv("SERVICE_USER_TRAP_ID", "")
	s := Service{Administrators: &stubAdminRepo{}}

	c, rec := newAuthContext("Bearer s3cret-token")
	got, _ := s.AuthUser(c)

	assert.Nil(t, got)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestBearerToken(t *testing.T) {
	c, _ := newAuthContext("Bearer abc123")
	assert.Equal(t, "abc123", bearerToken(c))

	c, _ = newAuthContext("bearer abc123") // case-insensitive scheme
	assert.Equal(t, "abc123", bearerToken(c))

	c, _ = newAuthContext("")
	assert.Equal(t, "", bearerToken(c))

	c, _ = newAuthContext("Basic abc123")
	assert.Equal(t, "", bearerToken(c))
}

func TestForwardedUser(t *testing.T) {
	mk := func(h string) echo.Context {
		c, _ := newAuthContext("")
		if h != "" {
			c.Request().Header.Set("X-Forwarded-User", h)
		}
		return c
	}
	t.Run("disabled returns empty even with header", func(t *testing.T) {
		t.Setenv("TRUST_FORWARD_AUTH", "0")
		assert.Equal(t, "", forwardedUser(mk("alice")))
	})
	t.Run("enabled returns header value", func(t *testing.T) {
		t.Setenv("TRUST_FORWARD_AUTH", "1")
		assert.Equal(t, "alice", forwardedUser(mk("alice")))
	})
	t.Run("enabled but no header returns empty", func(t *testing.T) {
		t.Setenv("TRUST_FORWARD_AUTH", "1")
		assert.Equal(t, "", forwardedUser(mk("")))
	})
	t.Run("X-Showcase-User fallback", func(t *testing.T) {
		t.Setenv("TRUST_FORWARD_AUTH", "1")
		c, _ := newAuthContext("")
		c.Request().Header.Set("X-Showcase-User", "bob")
		assert.Equal(t, "bob", forwardedUser(c))
	})
}

// Forward-auth: a proxy-asserted user authenticates as that trap_id; admin via list.
func TestAuthUser_Forwarded_Valid(t *testing.T) {
	t.Setenv("TRUST_FORWARD_AUTH", "1")
	s := Service{Administrators: &stubAdminRepo{admins: []string{"alice"}}}
	c, _ := newAuthContext("")
	c.Request().Header.Set("X-Forwarded-User", "alice")

	got, err := s.AuthUser(c)

	assert.NoError(t, err)
	assert.NotNil(t, got)
	user, _ := got.Get(contextUserKey).(model.User)
	assert.Equal(t, "alice", user.TrapId)
	assert.True(t, user.IsAdmin)
}

func TestAuthUser_Forwarded_NonAdmin(t *testing.T) {
	t.Setenv("TRUST_FORWARD_AUTH", "1")
	s := Service{Administrators: &stubAdminRepo{admins: []string{"someoneElse"}}}
	c, _ := newAuthContext("")
	c.Request().Header.Set("X-Forwarded-User", "bob")

	got, err := s.AuthUser(c)

	assert.NoError(t, err)
	user, _ := got.Get(contextUserKey).(model.User)
	assert.Equal(t, "bob", user.TrapId)
	assert.False(t, user.IsAdmin)
}

// The local-storage fallback (no Swift configured) creates the upload directory
// when it does not exist, instead of panicking — regression for the NeoShowcase
// "panic: dir doesn't exist" startup crash.
func TestNewImageRepository_LocalFallbackCreatesDir(t *testing.T) {
	t.Setenv("OS_AUTH_URL", "") // force the local-storage branch
	dir := filepath.Join(t.TempDir(), "uploads-nested")
	t.Setenv("UPLOAD_DIR", dir)

	repo := newImageRepository()

	assert.NotNil(t, repo)
	fi, err := os.Stat(dir)
	assert.NoError(t, err)
	assert.True(t, fi.IsDir())
}
