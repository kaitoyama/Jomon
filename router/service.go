//go:build !debug

package router

import (
	"crypto/subtle"
	"encoding/gob"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/traPtitech/Jomon/model"
	storagePkg "github.com/traPtitech/Jomon/storage"
)

func NewService() Service {
	traQClientId := os.Getenv("TRAQ_CLIENT_ID")
	webhookSecret := os.Getenv("WEBHOOK_SECRET")
	webhookChannelId := os.Getenv("WEBHOOK_CHANNEL_ID")
	webhookId := os.Getenv("WEBHOOK_ID")

	gob.Register(model.User{})

	return Service{
		Administrators: model.NewAdministratorRepository(),
		Applications:   model.NewApplicationRepository(),
		Comments:       model.NewCommentRepository(),
		Images:         newImageRepository(),
		Users:          model.NewUserRepository(),
		TraQAuth:       model.NewTraQAuthRepository(traQClientId),
		Webhook:        model.NewWebhookRepository(webhookSecret, webhookChannelId, webhookId),
	}
}

// newImageRepository builds the image store: Swift in production, falling back to
// ephemeral local storage when no Swift is configured (OS_AUTH_URL empty) — e.g. a
// NeoShowcase dev deploy with no object store. Local uploads are not durable
// (the container FS resets on restart), which is acceptable for dev; the payout
// flow does not touch images.
func newImageRepository() model.ApplicationsImageRepository {
	if os.Getenv("OS_AUTH_URL") == "" {
		dir := os.Getenv("UPLOAD_DIR")
		if dir == "" {
			dir = "./uploads"
		}
		// NewLocalStorage requires the directory to already exist; create it, since
		// the container FS starts empty (and resets on restart).
		if err := os.MkdirAll(dir, 0o755); err != nil {
			panic(err)
		}
		local, err := storagePkg.NewLocalStorage(dir)
		if err != nil {
			panic(err)
		}
		return model.NewApplicationsImageRepository(&local)
	}

	swift, err := storagePkg.NewSwiftStorage(
		os.Getenv("OS_CONTAINER"),
		os.Getenv("OS_USERNAME"),
		os.Getenv("OS_PASSWORD"),
		os.Getenv("OS_TENANT_NAME"),
		os.Getenv("OS_TENANT_ID"),
		os.Getenv("OS_AUTH_URL"),
	)
	if err != nil {
		panic(err)
	}
	return model.NewApplicationsImageRepository(&swift)
}

func EchoConfig(_ *echo.Echo) {}

func (s Service) AuthUser(c echo.Context) (echo.Context, error) {
	// Service-to-service auth (Checkin → Jomon payout write-back): a one-way
	// Bearer token. A request carrying an `Authorization: Bearer` header is
	// treated as a service call and authenticated ONLY against SERVICE_TOKEN — it
	// never falls through to the browser session path. Authorization is
	// unchanged: handlers still check IsAdmin(trapId), so SERVICE_USER_TRAP_ID
	// must be a Jomon administrator (it is also recorded as the repaid-by actor).
	if token := bearerToken(c); token != "" {
		return s.authServiceToken(c, token)
	}

	// Reverse-proxy forward-auth (NeoShowcase "Soft" member-auth): when enabled,
	// trust the proxy's X-Forwarded-User as the traQ identity. The browser is
	// authenticated by the platform, so Jomon needs no traQ OAuth of its own.
	if trapId := forwardedUser(c); trapId != "" {
		return s.authForwardedUser(c, trapId)
	}

	sess, err := session.Get(sessionKey, c)
	if err != nil {
		return nil, c.NoContent(http.StatusInternalServerError)
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   sessionDuration,
		HttpOnly: true,
	}

	accTok, ok := sess.Values[sessionAccessTokenKey].(string)
	if !ok || accTok == "" {
		return nil, c.NoContent(http.StatusUnauthorized)
	}
	c.Set(contextAccessTokenKey, accTok)

	user, ok := sess.Values[sessionUserKey].(model.User)
	if !ok {
		user, err = s.Users.GetMyUser(accTok)
		sess.Values[sessionUserKey] = user
		if err := sess.Save(c.Request(), c.Response()); err != nil {
			return nil, c.NoContent(http.StatusInternalServerError)
		}

		if err != nil {
			return nil, c.NoContent(http.StatusInternalServerError)
		}
	}

	admins, err := s.Administrators.GetAdministratorList()
	if err != nil {
		return nil, c.NoContent(http.StatusInternalServerError)
	}
	user.GiveIsUserAdmin(admins)

	c.Set(contextUserKey, user)

	return c, nil
}

// bearerToken returns the token from an `Authorization: Bearer <token>` header,
// or "" when the header is absent or is not a Bearer credential. Browsers
// authenticate to Jomon with a session cookie, not this header, so its presence
// marks a service-to-service call.
func bearerToken(c echo.Context) string {
	const prefix = "Bearer "
	h := c.Request().Header.Get(echo.HeaderAuthorization)
	if len(h) >= len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// forwardedUser returns the traQ ID asserted by the trusted reverse proxy
// (NeoShowcase "Soft" member-auth), or "" when not enabled/absent. Gated on
// TRUST_FORWARD_AUTH=1 so the header is only trusted where the platform proxy
// overwrites any client-supplied value. X-Forwarded-User is the current header;
// X-Showcase-User is kept for compatibility.
func forwardedUser(c echo.Context) string {
	if os.Getenv("TRUST_FORWARD_AUTH") != "1" {
		return ""
	}
	h := c.Request().Header.Get("X-Forwarded-User")
	if h == "" {
		h = c.Request().Header.Get("X-Showcase-User")
	}
	return strings.TrimSpace(h)
}

// authForwardedUser authenticates a browser request whose identity was asserted
// by the trusted proxy. It acts as that traQ user; admin authorization is still
// the DB-backed IsAdmin check in the handlers (admin via GetAdministratorList).
func (s Service) authForwardedUser(c echo.Context, trapId string) (echo.Context, error) {
	user := model.User{TrapId: trapId}
	admins, err := s.Administrators.GetAdministratorList()
	if err != nil {
		return nil, c.NoContent(http.StatusInternalServerError)
	}
	user.GiveIsUserAdmin(admins)

	c.Set(contextAccessTokenKey, "")
	c.Set(contextUserKey, user)

	return c, nil
}

// authServiceToken authenticates a Bearer service call. It succeeds only when
// SERVICE_TOKEN is configured and matches in constant time and
// SERVICE_USER_TRAP_ID is set; the request then acts as that traQ user (which
// must be a Jomon administrator for write operations). A present-but-invalid
// token is rejected with 401 rather than falling back to session auth.
func (s Service) authServiceToken(c echo.Context, token string) (echo.Context, error) {
	expected := os.Getenv("SERVICE_TOKEN")
	if expected == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
		return nil, c.NoContent(http.StatusUnauthorized)
	}

	trapId := os.Getenv("SERVICE_USER_TRAP_ID")
	if trapId == "" {
		return nil, c.NoContent(http.StatusUnauthorized)
	}

	user := model.User{TrapId: trapId}
	admins, err := s.Administrators.GetAdministratorList()
	if err != nil {
		return nil, c.NoContent(http.StatusInternalServerError)
	}
	user.GiveIsUserAdmin(admins)

	c.Set(contextAccessTokenKey, "")
	c.Set(contextUserKey, user)

	return c, nil
}
