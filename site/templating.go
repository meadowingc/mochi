package site

import (
	"encoding/json"
	"log"
	"mochi/constants"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/open2b/scriggo"
	"github.com/open2b/scriggo/builtin"
	"github.com/open2b/scriggo/native"
)

func RenderTemplate(w http.ResponseWriter, r *http.Request, templateName string, extraDeclarations *native.Declarations) {

	signedInUser := GetSignedInUserOrNil(r)

	opts := &scriggo.BuildOptions{
		Globals: native.Declarations{
			"isDebug":      constants.DEBUG_MODE,
			"publicURL":    constants.PUBLIC_URL,
			"appName":      constants.APP_NAME,
			"signedInUser": &signedInUser,
			"min":          builtin.Min,
			"max":          builtin.Max,
			"escapePath": func(path string) string {
				return url.PathEscape(path)
			},
			"dateFmt": func(layout string, t time.Time) string {
				return t.Format(layout)
			},
			"now": func() time.Time {
				return time.Now()
			},
			"toJSON": func(v interface{}) string {
				jsonData, err := json.Marshal(v)
				if err != nil {
					log.Printf("Error marshaling to JSON: %v", err)
					return ""
				}
				return string(jsonData)
			},
		},
	}

	if extraDeclarations != nil {
		for k, v := range *extraDeclarations {
			opts.Globals[k] = v
		}
	}

	fs := os.DirFS("templates")

	template, err := scriggo.BuildTemplate(fs, templateName, opts)

	if err != nil {
		log.Printf("Error building template %s: %v", templateName, err)
		return
	}

	// write mime type
	if strings.HasSuffix(templateName, ".html") {
		w.Header().Set("Content-Type", "text/html")
	} else if strings.HasSuffix(templateName, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(templateName, ".js") {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	}

	err = template.Run(w, map[string]any{}, nil)

	if err != nil {
		log.Printf("Template execution error for template %s: %v", templateName, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
