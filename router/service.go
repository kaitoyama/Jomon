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

	traQClientId := os.Getenv("TRAQ_CLIENT_ID")
	webhookSecret := os.Getenv("WEBHOOK_SECRET")
	webhookChannelId := os.Getenv("WEBHOOK_CHANNEL_ID")
	webhookId := os.Getenv("WEBHOOK_ID")

	gob.Register(model.User{})

	return Service{
		Administrators: model.NewAdministratorRepository(),
		Applications:   model.NewApplicationRepository(),
		Comments:       model.NewCommentRepository(),
		Images:         model.NewApplicationsImageRepository(&swift),
		Users:          model.NewUserRepository(),
		TraQAuth:       model.NewTraQAuthRepository(traQClientId),
		Webhook:        model.NewWebhookRepository(webhookSecret, webhookChannelId, webhookId),
	}
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
