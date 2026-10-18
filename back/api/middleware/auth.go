package middleware

import (
    "net/http"

    "github.com/labstack/echo/v4"
    "github.com/pavlith/zzz/back/auth"
    "gorm.io/gorm"
)

const UserIDKey = "user_id"

func RequireBearer(db *gorm.DB) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            id, err := auth.Authenticate(db, c.Request().Header.Get("Authorization"))
            if err != nil {
                return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
            }
            c.Set(UserIDKey, id)
            return next(c)
        }
    }
}
