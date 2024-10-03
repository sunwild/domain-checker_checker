package domains

import "time"

type CheckResult struct {
	Domain           string    `json:"domain"`
	HTTPStatus       int       `json:"http_status"`
	DNSStatus        string    `json:"dns_status"`
	SSLStatus        string    `json:"ssl_status"`
	VirusTotalStatus string    `json:"virus_total_status"`
	CheckedAt        time.Time `json:"checked_at"`
}
