package grpcchecker

import (
	"context"
	pkgApiD "github.com/sunwild/domain-checker_api/pkg/domains"
	"github.com/sunwild/domain-checker_checker/internal/service"
	pb "github.com/sunwild/domain-checker_checker/proto/checker/proto"
	"log"
	"strings"
	"sync"
)

type CheckerServer struct {
	pb.UnimplementedDomainCheckerServer
}

func (s *CheckerServer) CheckDomains(ctx context.Context, req *pb.DomainRequest) (*pb.DomainResponse, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var response pb.DomainResponse

	log.Printf("получен запрос Checkdomain для доменов: %v", req.Domains)

	for _, domainName := range req.Domains {
		// Проверяем, начинается ли домен с протокола (http:// или https://)
		if !strings.HasPrefix(domainName, "http://") && !strings.HasPrefix(domainName, "https://") {
			domainName = "http://" + domainName // Используем http:// по умолчанию
		}

		domainWithoutProtocol := strings.TrimPrefix(strings.TrimPrefix(domainName, "http://"), "https://")

		wg.Add(1)
		go func(domain string) {
			defer wg.Done()

			log.Printf("СТАРТ ПРОВЕРКИ ДОМЕНА: %s", domain)
			domainStruct := pkgApiD.Domain{Name: domain}

			// Логируем начало проверки домена
			log.Printf("Проверка домена: %s", domainStruct.Name)

			status, err := service.CheckDomain(domainStruct, req.IsManual)
			if err != nil {
				log.Printf("ошибка проверки домена %s: %v", domain, err)
				// Записываем ошибочный статус только один раз
				mu.Lock()
				domainStatus := &pb.DomainStatus{
					Domain:           domainStruct.Name,
					HttpStatus:       408, // Пример кода для ошибки
					DnsStatus:        "Error",
					SslStatus:        "Error",
					VirusTotalStatus: "Error",
				}
				response.Statuses = append(response.Statuses, domainStatus)
				mu.Unlock()
				return
			}

			// Логируем успешную проверку домена
			log.Printf("ПРОВЕРКА Domain: %s ЗАВЕРШЕНА, HTTP STATUS: %d", status.Domain, status.StatusCode)
			mu.Lock()
			domainStatus := &pb.DomainStatus{
				Domain:           status.Domain,
				HttpStatus:       int32(status.StatusCode),
				DnsStatus:        status.DnsStatus,
				SslStatus:        status.SslStatus,
				VirusTotalStatus: status.VirusTotal,
			}

			response.Statuses = append(response.Statuses, domainStatus)
			mu.Unlock()
		}(domainWithoutProtocol)
	}

	wg.Wait()
	log.Printf("Completed CheckDomains request for domains: %v", req.Domains)
	return &response, nil
}
