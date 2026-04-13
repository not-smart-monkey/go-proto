package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	numWorkers    = 1000
	maxPort       = 10000
	timeout       = 2 * time.Second
	throttleDelay = 10 * time.Millisecond
)

type ScanResult struct {
	Port    int
	Open    bool
	Elapsed time.Duration
}

func worker(ctx context.Context, ports <-chan int, results chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case port, ok := <-ports:
			if !ok {
				return
			}

			select {
			case <-ctx.Done():
				return
			default:
				start := time.Now()
				address := fmt.Sprintf("scanme.nmap.org:%d", port)
				conn, err := net.DialTimeout("tcp", address, timeout)
				elapsed := time.Since(start)

				if err == nil {
					conn.Close()
					results <- ScanResult{Port: port, Open: true, Elapsed: elapsed}
				} else {
					results <- ScanResult{Port: port, Open: false, Elapsed: elapsed}
				}
			}

		case <-ctx.Done():
			return
		}
	}
}

func drawProgressBar(current, total int32, openPorts []int) {
	width := 50
	percent := float64(current) / float64(total)
	bar := strings.Repeat("=", int(float64(width)*percent))
	spaces := strings.Repeat(" ", width-len(bar))

	fmt.Printf("\r[%s%s] %d/%d (%.1f%%) | Open: %v",
		bar, spaces, current, total, percent*100, openPorts)
}

func main() {
	startTime := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Каналы для данных
	ports := make(chan int, numWorkers)
	results := make(chan ScanResult, numWorkers)

	// Обработка сигналов
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Горутина для обработки прерывания
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, initiating graceful shutdown...")
		cancel() // Отменяем контекст

		// Даем время на завершение
		select {
		case <-time.After(3 * time.Second):
			fmt.Println("Graceful shutdown timeout exceeded, forcing exit")
			os.Exit(1)
		case <-ctx.Done():
		}
	}()

	var wg sync.WaitGroup
	var openPorts []int
	var openPortsMutex sync.Mutex
	var scanned int32

	// Запуск воркеров
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(ctx, ports, results, &wg)
	}

	// Обработка результатов
	go func() {
		for {
			select {
			case result, ok := <-results:
				if !ok {
					return
				}
				current := atomic.AddInt32(&scanned, 1)
				if result.Open {
					openPortsMutex.Lock()
					openPorts = append(openPorts, result.Port)
					openPortsMutex.Unlock()
				}
				drawProgressBar(current, maxPort, openPorts)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Отправка портов
	go func() {
		defer close(ports)
		for port := 1; port <= maxPort; port++ {
			select {
			case ports <- port:
				time.Sleep(throttleDelay)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Ожидание завершения
	wg.Wait()
	close(results)

	// Сортировка результатов
	openPortsMutex.Lock()
	sort.Ints(openPorts)
	openPortsMutex.Unlock()

	// Финальный отчет
	fmt.Printf("\n\nScan Report\n")
	fmt.Printf("-----------\n")
	fmt.Printf("Scanned ports: %d/%d\n", scanned, maxPort)
	fmt.Printf("Open ports: %d\n", len(openPorts))
	if len(openPorts) > 0 {
		fmt.Printf("List of open ports: %v\n", openPorts)
	}
	fmt.Printf("Scan duration: %.2f seconds\n", time.Since(startTime).Seconds())
}
