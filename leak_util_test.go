package anoncred

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

func assertNoLeak(p *Presentation, secrets []string) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	for _, s := range secrets {
		if bytes.Contains(raw, []byte(s)) {
			return fmt.Errorf("secret %q leaked: %s", s, raw)
		}
	}
	if strings.Contains(string(raw), "\"Int\":29") {
		return fmt.Errorf("undisclosed age leaked: %s", raw)
	}
	return nil
}
