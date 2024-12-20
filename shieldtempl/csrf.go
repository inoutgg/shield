package shieldtempl

import (
	"context"
	"io"

	"github.com/a-h/templ"
	"go.inout.gg/shield/shieldcsrf"
)

// CsrfToken returns a component that renders a CSRF token as an input field.
func CsrfToken(name string) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		tok, err := shieldcsrf.FromContext(ctx)
		if err != nil {
			return err
		}

		_, err = w.Write(
			[]byte(
				"<input type=\"hidden\" name=\"" + name + "\"" + "value=\"" + tok.String() + "\">",
			),
		)

		return err
	})
}
