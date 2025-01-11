package database

import (
	"net/url"
	"strings"
)

func (d *DatabaseImage) GetDatabaseImageUrl(rKeyString string) string {
	encodingUrl := new(url.URL)
	encodingUrl.Path = d.Path
	encodingUrl.Host = d.Domain
	encodingUrl.Scheme = "https"
	encodingUrl.RawQuery = d.Query
	if rKeyString != "" {
		rKeyString = strings.TrimPrefix(rKeyString, "?")
		parts := strings.Split(rKeyString, "=")
		if len(parts) == 2 {
			encodingUrl.Query().Add(parts[0], parts[1])
		}
	}
	encodingUrl.Query().Add("spec", "0")
	return encodingUrl.String()
}
