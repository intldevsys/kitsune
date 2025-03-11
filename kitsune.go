package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"
)

type ScanResult struct {
	IP       string
	FilePath string
}

var (
	fileMu         sync.Mutex
	resultsFile    *os.File
	activeScans    = make(map[string]context.CancelFunc)
	activeScansMu  sync.Mutex
	pauseMu        sync.RWMutex
	paused         bool
	fileIPMu       sync.Mutex //Mutex for IP file operations
)

func initResultsFile() {
	var err error
	resultsFile, err = os.OpenFile("results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening results file: %v", err)
	}
}

// MODIFICATION: Function to remove IP from ips.txt
func removeIPFromFile(ip, filePath string) {
	fileIPMu.Lock()
	defer fileIPMu.Unlock()

	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening IP file: %v", err)
		return
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		existingIP := strings.TrimSpace(scanner.Text())
		if existingIP != "" && existingIP != ip {
			ips = append(ips, existingIP)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading IP file: %v", err)
		return
	}

	content := []byte(strings.Join(ips, "\n") + "\n")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		log.Printf("Error writing IP file: %v", err)
	}
}

func writeToFile(result ScanResult) {
	fileMu.Lock()
	defer fileMu.Unlock()

	_, err := fmt.Fprintf(resultsFile, "[%s] %s\n", result.IP, result.FilePath)
	if err != nil {
		log.Printf("Error writing to results file: %v", err)
	}
	resultsFile.Sync()
}

func waitIfPaused() {
	pauseMu.RLock()
	pauseMu.RUnlock()
}

func scanFTP(ctx context.Context, cancel context.CancelFunc, ip string, include, exclude []string, maxDepth int, resultCh chan<- ScanResult) {
	fileCount := 0 // Track number of files found
	defer cancel() // Ensure context is canceled when function exits

	addr := fmt.Sprintf("%s:21", ip)
	conn, err := ftp.Dial(addr, ftp.DialWithTimeout(5*time.Second))
	if err != nil {
		log.Printf("Error connecting to %s: %v", ip, err)
		return
	}
	defer conn.Quit()

	if err = conn.Login("anonymous", "anonymous"); err != nil {
		log.Printf("Login failed for %s: %v", ip, err)
		return
	}

	var recursiveScan func(ctx context.Context, path string, depth int)
	recursiveScan = func(ctx context.Context, path string, depth int) {
		if depth > maxDepth {
			return
		}
		waitIfPaused()
		select {
		case <-ctx.Done():
			return
		default:
		}

		entries, err := conn.List(path)
		if err != nil {
			return
		}

		for _, entry := range entries {
			waitIfPaused()
			select {
			case <-ctx.Done():
				return
			default:
			}

			fullPath := strings.TrimRight(path, "/") + "/" + entry.Name
			if entry.Type == ftp.EntryTypeFolder {
				recursiveScan(ctx, fullPath, depth+1)
			} else if entry.Type == ftp.EntryTypeFile {
				valid := true
				if len(include) > 0 {
					valid = false
					for _, ext := range include {
						if strings.HasSuffix(entry.Name, ext) {
							valid = true
							break
						}
					}
				}
				if valid && len(exclude) > 0 {
					for _, ext := range exclude {
						if strings.HasSuffix(entry.Name, ext) {
							valid = false
							break
						}
					}
				}

				if valid {
					// MODIFICATION: Check file count before processing
					if fileCount >= 8000 {
						log.Printf("Reached 8000 files for %s, stopping scan", ip)
						cancel()
						return
					}

					result := ScanResult{IP: ip, FilePath: fullPath}
					resultCh <- result
					writeToFile(result)
					fileCount++
				}
			}
		}
	}

	recursiveScan(ctx, "/", 0)
}

func main() {
	ipListPath := flag.String("ips", "ips.txt", "Path to IP list file")
	includeTypes := flag.String("include", "", "Comma-separated file extensions to include")
	excludeTypes := flag.String("exclude", "", "Comma-separated file extensions to exclude")
	maxDepth := flag.Int("depth", 3, "Maximum directory depth")
	flag.Parse()

	ipFilePath := *ipListPath // Store path for later use
	file, err := os.Open(ipFilePath)
	if err != nil {
		log.Fatalf("Failed to open IP list file: %v", err)
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading IP list: %v", err)
	}

	var includes, excludes []string
	if *includeTypes != "" {
		includes = strings.Split(*includeTypes, ",")
		for i := range includes {
			includes[i] = strings.TrimSpace(includes[i])
		}
	}
	if *excludeTypes != "" {
		excludes = strings.Split(*excludeTypes, ",")
		for i := range excludes {
			excludes[i] = strings.TrimSpace(excludes[i])
		}
	}

	initResultsFile()
	defer resultsFile.Close()

	resultCh := make(chan ScanResult, 100)
	var wg sync.WaitGroup

	go func() {
		inputReader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Enter command (p to pause/resume, - to remove IP): ")
			line, err := inputReader.ReadString('\n')
			if err != nil {
				log.Printf("Error reading input: %v", err)
				continue
			}
			cmd := strings.TrimSpace(line)
			if cmd == "p" {
				if !paused {
					pauseMu.Lock()
					paused = true
					fmt.Println("Scanning paused.")
				} else {
					paused = false
					pauseMu.Unlock()
					fmt.Println("Scanning resumed.")
				}
			} else if cmd == "-" {
				fmt.Print("Enter IP to remove: ")
				ipToRemove, err := inputReader.ReadString('\n')
				if err != nil {
					log.Printf("Error reading IP: %v", err)
					continue
				}
				ipToRemove = strings.TrimSpace(ipToRemove)
				activeScansMu.Lock()
				if cancelFunc, exists := activeScans[ipToRemove]; exists {
					cancelFunc()
					delete(activeScans, ipToRemove)
					fmt.Printf("Removed IP %s from scanning.\n", ipToRemove)
				} else {
					fmt.Printf("IP %s not found among active scans.\n", ipToRemove)
				}
				activeScansMu.Unlock()
			}
		}
	}()

	for _, ip := range ips {
		ctx, cancel := context.WithCancel(context.Background())
		activeScansMu.Lock()
		activeScans[ip] = cancel
		activeScansMu.Unlock()

		wg.Add(1)
		go func(ip string, ctx context.Context, cancel context.CancelFunc) {
			defer wg.Done()
			scanFTP(ctx, cancel, ip, includes, excludes, *maxDepth, resultCh)
			
			activeScansMu.Lock()
			delete(activeScans, ip)
			activeScansMu.Unlock()
			
			// Remove IP from file whether scan completed or was stopped
			removeIPFromFile(ip, ipFilePath)
		}(ip, ctx, cancel)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for res := range resultCh {
		fmt.Printf("[%s] %s\n", res.IP, res.FilePath)
	}

	fmt.Println("Scanning completed.")
}
