package site

import (
	"log"
	"mochi/constants"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/open2b/scriggo"
	"github.com/open2b/scriggo/builtin"
	"github.com/open2b/scriggo/native"
)

var templatesCache sync.Map

func RenderTemplate(w http.ResponseWriter, r *http.Request, templateName string, data any) {

	actualTemplate, ok := templatesCache.Load(templateName)
	if !ok || constants.DEBUG_MODE {

		opts := &scriggo.BuildOptions{
			Globals: native.Declarations{
				"min": builtin.Min,
				"max": builtin.Max,
				"dateFmt": func(layout string, t time.Time) string {
					return t.Format(layout)
				},
				"now": func() time.Time {
					return time.Now()
				},
				"isDebug":   constants.DEBUG_MODE,
				"publicURL": constants.PUBLIC_URL,
				"appName":   constants.APP_NAME,
				// "who": (*string)(nil)
			},
		}

		fs := os.DirFS("templates")
		template, err := scriggo.BuildTemplate(fs, templateName, opts)

		if err != nil {
			log.Printf("Error building template %s: %v", templateName, err)
			return
		}

		templatesCache.Store(templateName, template)
		actualTemplate = template
	}

	templateData := map[string]any{
		"Global": map[string]any{
			"IsDebug":   constants.DEBUG_MODE,
			"SiteName":  constants.APP_NAME,
			"PublicURL": constants.PUBLIC_URL,
		},
		"Data": data,
	}

	err := actualTemplate.(*scriggo.Template).Run(w, templateData, nil)

	if err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// write mime type
	if strings.HasSuffix(templateName, ".html") {
		w.Header().Set("Content-Type", "text/html")
	}

}
