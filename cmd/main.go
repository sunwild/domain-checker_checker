package main

import (
	"encoding/json"
	"fmt"
	pkgApiD "github.com/sunwild/domain-checker_api/pkg/domains"
	"github.com/sunwild/domain-checker_checker/internal/service"
	pb "github.com/sunwild/domain-checker_checker/proto/checker/proto"
	"github.com/sunwild/domain_checker/internal/grpcchecker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

func main() {
	fmt.Println("Starting Domain Checker gRPC Server...")

	go startPeriodicChecks()

	lis, err := net.Listen("tcp", ":50051") // Запускаем gRPC сервер на порту 50051
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterDomainCheckerServer(s, &grpcchecker.CheckerServer{})

	reflection.Register(s)

	log.Printf("Server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func startPeriodicChecks() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C
		log.Println("ВНИМАНИЕ: СТАРТ ПЕРЕОДИЧЕСКОЙ ПРОВЕРКИ ДОМЕНОВ...")

		// Получаем список доменов из API
		domains, err := fetchDomainsFromAPI()
		if err != nil {
			log.Printf("ошибка получения доменов для переодической проверки: %v", err)
			continue
		}

		// Асинхронная проверка всех доменов
		var wg sync.WaitGroup
		for _, domain := range domains {
			wg.Add(1)

			go func(domain pkgApiD.Domain) {
				defer wg.Done()
				_, err := service.CheckDomain(domain, false) // Передаем false для автоматической проверки
				if err != nil {
					log.Printf("ПЕРЕОДИЧЕСКАЯ ПРОВЕРКА: ОШИБКА ПРОВЕРКИ ДОМЕНА %s: %v", domain.Name, err)
				}
			}(domain)
		}

		wg.Wait() // Ждем завершения всех асинхронных задач

		log.Println("ВНИМАНИЕ:ПЕРЕОДИЧЕСКАЯ ПРОВЕРКА ДОМЕНОВ ЗАВЕРШЕНА.")
	}
}

// Функция для получения списка доменов из API
func fetchDomainsFromAPI() ([]pkgApiD.Domain, error) {
	resp, err := http.Get("http://localhost:8000/domains") // Указываем URL API
	if err != nil {
		return nil, fmt.Errorf("failed to fetch domains: %v", err)
	}
	defer resp.Body.Close()

	var domains []pkgApiD.Domain
	if err := json.NewDecoder(resp.Body).Decode(&domains); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return domains, nil
}
