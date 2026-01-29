package render

import (
	"testing"

	"github.com/emphereio/ovrse/pkg/inventory"
	"github.com/emphereio/ovrse/pkg/ovrs"
)

func TestRenderTemplateSections(t *testing.T) {
	template := &ovrs.Template{
		Preflight: []ovrs.Check{
			{
				ID:   "check_service",
				Kind: "os.check_service",
				Params: map[string]any{
					"service": "{{ targetService }}",
				},
			},
		},
		Steps: []ovrs.Step{
			{
				ID:   "http_call",
				Kind: "http.get",
				Params: map[string]any{
					"url":    "http://{{ inventory.hostname }}/health",
					"header": map[string]any{"x-env": "{{ envName }}"},
					"attempts": []any{
						map[string]any{"timeout": "{{ timeoutSeconds }}"},
					},
				},
			},
		},
		Validation: []ovrs.Check{
			{
				ID:   "check_version",
				Kind: "os.check_version",
				Params: map[string]any{
					"package": "{{ targetPackage }}",
					"version": "{{ targetVersion }}",
				},
			},
		},
	}

	ctx := RenderContext{
		Host: inventory.Host{
			ID: "web-01",
		},
		Parameters: map[string]any{
			"targetService":  "nginx",
			"targetPackage":  "nginx",
			"targetVersion":  "1.24.0",
			"envName":        "prod",
			"timeoutSeconds": 30,
		},
	}

	rendered, errs := RenderTemplateSections(template, ctx)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %v", errs)
	}

	if rendered.Preflight[0].Params["service"] != "nginx" {
		t.Fatalf("expected service param to be nginx, got %v", rendered.Preflight[0].Params["service"])
	}

	url := rendered.Steps[0].Params["url"]
	if url != "http://web-01/health" {
		t.Fatalf("expected url http://web-01/health, got %v", url)
	}

	header := rendered.Steps[0].Params["header"].(map[string]any)
	if header["x-env"] != "prod" {
		t.Fatalf("expected header x-env=prod, got %v", header["x-env"])
	}

	attempts := rendered.Steps[0].Params["attempts"].([]any)
	if attempts[0].(map[string]any)["timeout"] != "30" {
		t.Fatalf("expected timeout 30, got %v", attempts[0].(map[string]any)["timeout"])
	}
}
