# kitsune

## **Summary**

A simple, high-performance FTP scanning utility written in Go, featuring intelligent IP list management and resource controls.  Can effectively crawl hundreds of thousands of anonymous FTP servers while maintaining operational efficiency through automatic IP list updates and scan throttling.


## Key Features
1. **Progressive IP List Management**
   - Auto-removal of processed IPs from `ips.txt`
   - Prevention of duplicate scans through real-time file updates
   - Manual IP removal during active operations

2. **Resource Controls**
   - Automatic scan termination at 8,000 files/IP (modify to your preference)
   - Configurable directory depth (-depth flag)
   - File extension filters (include/exclude lists)

3. **Operational Flexibility**
   - Pause/resume functionality
   - Concurrent scanning with goroutine management
   - Context-aware cancellation propagation

4. **Audit & Reporting**
   - Real-time results display
   - Persistent `results.txt` logging
   - Scan progress monitoring
