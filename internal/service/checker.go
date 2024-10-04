package service

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	//pkgApiD "github.com/sunwild/api/pkg/domains"
	database "github.com/sunwild/domain-checker_checker/internal/datebase"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func CheckDomain(domain pkgApiD.Domain, isManual bool) (*pkgApiD.DomainStatus, error) {
	var dnsStatus, sslStatus, virusTotalStatus string

	httpStatus, err := CheckHTTP(domain.Name)
	if err != nil {
		log.Printf("Error checking HTTP status for domain %s: %v", domain.Name, err)
		httpStatus = 408 | 0 // Устанавливаем код ошибки (таймаут)
		dnsStatus = "Error"
		sslStatus = "Error"
		virusTotalStatus = "Error"
	} else {
		// Выполняем остальные проверки, только если HTTP статус не 408
		dnsStatus, err = CheckDNS(domain.Name)
		if err != nil {
			log.Printf("Error checking DNS status for domain %s: %v", domain.Name, err)
			dnsStatus = "Ошибка DNS: " + err.Error()
		}

		sslStatus, err = CheckSSL(domain.Name)
		if err != nil {
			log.Printf("Error checking SSL status for domain %s: %v", domain.Name, err)
			sslStatus = "Ошибка SSL: " + err.Error()
		}

		virusTotalStatus, err = CheckVirusTotal(domain.Name, "78294ae0b56d4b2fee16f176ccda360c2fb62690a2c8d7bf1eb0b4be6c218a31")
		if err != nil {
			log.Printf("Error checking VirusTotal status for domain %s: %v", domain.Name, err)
			virusTotalStatus = "Ошибка VirusTotal: " + err.Error()
		}
	}

	status := &pkgApiD.DomainStatus{
		Domain:     domain.Name,
		StatusCode: httpStatus,
		DnsStatus:  dnsStatus,
		SslStatus:  sslStatus,
		VirusTotal: virusTotalStatus,
	}

	// Сохраняем результат в соответствующую таблицу
	if isManual {
		if err := SaveManualCheckResult(status); err != nil {
			log.Printf("ОШИБКА СОХРАНЕНИЯ РЕЗУЛЬТАТА РУЧНОЙ ПРОВЕРКИ ДЛЯ ДОМЕНА %s: %v", domain.Name, err)
			return nil, err
		}
	} else {
		if err := SaveCheckResult(status); err != nil {
			log.Printf("ОШИБКА СОХРАНЕНИЯ РЕЗУЛЬТАТА ПЕРЕОДИЧЕСКОЙ ПРОВЕРКИ ДЛЯ ДОМЕНА %s: %v", domain.Name, err)

			return nil, err
		}
	}

	return status, nil
}

func CheckHTTP(domain string) (int, error) {
	// Добавляем протокол по умолчанию, если его нет
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "http://" + domain
	}

	client := &http.Client{
		Timeout: 20 * time.Second, // Тайм-аут для каждого HTTP-запроса
	}

	resp, err := client.Get(domain)
	if err != nil {
		return 0, fmt.Errorf("ошибка проверки HTTP статуса для %s: %v", domain, err)
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

func CheckDNS(domain string) (string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", fmt.Errorf("ошибка DNS: %v", err)
	}
	return fmt.Sprintf("IP адрес/а: %v", ips), nil
}

func CheckSSL(domain string) (string, error) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{})
	if err != nil {
		return "", fmt.Errorf("ошибка проверки SSL: %v", err)
	}
	defer conn.Close()

	for _, cert := range conn.ConnectionState().PeerCertificates {
		if cert.NotAfter.Before(time.Now()) {
			return "SSL просрочен", nil
		}
		return fmt.Sprintf("SSL действителен до: %s", cert.NotAfter.String()), nil
	}
	return "", fmt.Errorf("ошибка SSL")
}

func CheckVirusTotal(domainWithoutProtocol, apiKey string) (string, error) {

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domainWithoutProtocol)
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("ошибка создания запроса к VirusTotal: %v", err)
	}

	req.Header.Add("x-apikey", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("VirusTotal ошибка получения ответа: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("ошибка декодирования ответа от VirusTotal: %v", err)
	}

	// Извлекаем нужные атрибуты
	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return "Ошибка: неверный формат данных от VirusTotal", nil
	}

	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return "Ошибка: не найдены атрибуты в данных от VirusTotal", nil
	}

	// Анализируем "last_analysis_stats"
	lastAnalysisStats, ok := attributes["last_analysis_stats"].(map[string]interface{})
	if !ok {
		return "Ошибка: не найдены статистические данные от VirusTotal", nil
	}

	malicious := int(lastAnalysisStats["malicious"].(float64))
	suspicious := int(lastAnalysisStats["suspicious"].(float64))
	undetected := int(lastAnalysisStats["undetected"].(float64))
	harmless := int(lastAnalysisStats["harmless"].(float64))

	// Формируем результат
	var status []string
	if malicious > 0 {
		status = append(status, fmt.Sprintf("Ресурс заражен - %d", malicious))
	}
	if suspicious > 0 {
		status = append(status, fmt.Sprintf("Ресурс подозрителен - %d", suspicious))
	}

	if len(status) == 0 {
		status = append(status, fmt.Sprintf("Ресурс безопасен - Ненайдено %d, Безвредный %d", undetected, harmless))
	}

	return strings.Join(status, ", "), nil
}

// Сохранение результата автоматической проверки в таблицу domain_checks
func SaveCheckResult(status *pkgApiD.DomainStatus) error {
	db, err := database.NewDB()
	if err != nil {
		log.Printf("ПЕРЕОДИЧЕСКАЯ ПРОВЕРКА:ошибка подключения к базе данных: %v", err)
		return err
	}
	defer db.Conn.Close()

	query := `
        INSERT INTO domain_checks (domain, http_status, dns_status, ssl_status, virus_total_status, checked_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `

	_, err = db.Conn.Exec(query, status.Domain, status.StatusCode, status.DnsStatus, status.SslStatus, status.VirusTotal, time.Now())
	if err != nil {
		log.Printf("ПЕРЕОДИЧЕСКАЯ ПРОВЕРКА:ОШИБКА СОХРАНЕНИЯ ДАННЫХ ДЛЯ ДОМЕНА %s: %v", status.Domain, err)
		return err
	}

	log.Printf("ПЕРЕОДИЧЕСКАЯ ПРОВЕРКА:ДАННЫЕ УСПЕШНО СОХРАНЕНЫ ДЛЯ ДОМЕНА %s", status.Domain)
	return nil
}

// Сохранение результата ручной проверки в таблицу manual_checks
func SaveManualCheckResult(status *pkgApiD.DomainStatus) error {
	db, err := database.NewDB()
	if err != nil {
		log.Printf("ошибка подключения к базе данных: %v", err)
		return err
	}
	defer db.Conn.Close()

	query := `
        INSERT INTO manual_checks (domain, http_status, dns_status, ssl_status, virus_total_status, checked_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `

	_, err = db.Conn.Exec(query, status.Domain, status.StatusCode, status.DnsStatus, status.SslStatus, status.VirusTotal, time.Now())
	if err != nil {
		log.Printf("ОШИБКА СОХРАНЕНИЯ ДАННЫХ ДЛЯ ДОМЕНА  %s: %v", status.Domain, err)
		return err
	}

	log.Printf("ДАННЫЕ УСПЕШНО СОХРАНЕНЫ ДЛЯ ДОМЕНА %s", status.Domain)
	return nil
}
