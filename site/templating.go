package site

import (
	"bytes"
	"encoding/json"
	"log"
	"mochi/constants"
	"mochi/database"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/open2b/scriggo"
	"github.com/open2b/scriggo/builtin"
	"github.com/open2b/scriggo/native"
	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/html"
	"github.com/tdewolff/minify/v2/js"
)

var minifier *minify.M

var templateCache sync.Map

type CustomDeclaration struct {
	TypeDef, Value any
}

func RenderTemplate(
	w http.ResponseWriter,
	r *http.Request,
	templateName string,
	extraDeclarations *map[string]CustomDeclaration,
) {
	if minifier == nil {
		minifier = minify.New()
		minifier.Add("text/html", &html.Minifier{
			KeepDefaultAttrVals: true,
			KeepDocumentTags:    true,
			KeepEndTags:         true,
			KeepQuotes:          true,
		})
		minifier.Add("text/javascript", &js.Minifier{})
		minifier.Add("text/css", &css.Minifier{})
	}

	// Check if the template is already cached
	cachedTemplate, ok := templateCache.Load(templateName)
	if !ok || constants.DEBUG_MODE {
		opts := &scriggo.BuildOptions{
			Globals: native.Declarations{
				"signedInUser": (**database.User)(nil),
				"isDebug":      constants.DEBUG_MODE,
				"publicURL":    constants.PUBLIC_URL,
				"appName":      constants.APP_NAME,
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
				opts.Globals[k] = v.TypeDef
			}
		}

		fs := os.DirFS("templates")

		template, err := scriggo.BuildTemplate(fs, templateName, opts)
		if err != nil {
			log.Printf("Error building template %s: %v", templateName, err)
			return
		}

		templateCache.Store(templateName, template)
		cachedTemplate = template
	}

	template := cachedTemplate.(*scriggo.Template)

	// write mime type
	if strings.HasSuffix(templateName, ".html") {
		w.Header().Set("Content-Type", "text/html")
	} else if strings.HasSuffix(templateName, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(templateName, ".js") {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	}

	runTemplateData := map[string]any{
		"signedInUser": GetSignedInUserOrNil(r),
	}

	if extraDeclarations != nil {
		for k, v := range *extraDeclarations {
			runTemplateData[k] = v.Value
		}
	}

	var buf bytes.Buffer
	err := template.Run(&buf, runTemplateData, nil)
	if err != nil {
		log.Printf("Template execution error for template %s: %v", templateName, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var minifiedBuf bytes.Buffer
	contentType := w.Header().Get("Content-Type")
	if !constants.DEBUG_MODE && (contentType == "text/html" || contentType == "text/javascript; charset=utf-8") {
		err = minifier.Minify(contentType, &minifiedBuf, &buf)
		if err != nil {
			log.Printf("Minification error for template %s: %v", templateName, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = minifiedBuf.WriteTo(w)
	} else {
		_, err = buf.WriteTo(w)
	}

	if err != nil {
		log.Printf("Error writing response for template %s: %v", templateName, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
