// Package scanner provides the worker pool implementation for concurrent scanning.
package scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// WorkerPool manages a pool of workers for concurrent scan operations.
type WorkerPool struct {
	workers    int
	jobQueue   chan Job
	resultChan chan ScanResult
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	scanners   []Scanner

	// Metrics
	processedCount atomic.Int64
	errorCount     atomic.Int64
}

// Job represents a unit of work for the worker pool.
type Job struct {
	Target Target
	Config *ScanConfig
}

// NewWorkerPool creates a new worker pool with the specified number of workers.
func NewWorkerPool(ctx context.Context, workers int, scanners []Scanner) *WorkerPool {
	poolCtx, cancel := context.WithCancel(ctx)

	pool := &WorkerPool{
		workers:    workers,
		jobQueue:   make(chan Job, workers*2), // Buffered channel for backpressure
		resultChan: make(chan ScanResult, workers*2),
		ctx:        poolCtx,
		cancel:     cancel,
		scanners:   scanners,
	}

	return pool
}

// Start initializes and starts the worker goroutines.
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
}

// worker is the main goroutine that processes jobs from the queue.
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case job, ok := <-wp.jobQueue:
			if !ok {
				return
			}
			result := wp.processJob(job)
			wp.processedCount.Add(1)
			if result.Error != nil {
				wp.errorCount.Add(1)
			}

			select {
			case wp.resultChan <- result:
			case <-wp.ctx.Done():
				return
			}
		}
	}
}

// processJob executes all registered scanners on a target.
func (wp *WorkerPool) processJob(job Job) ScanResult {
	result := ScanResult{
		Target: job.Target,
	}

	startTime := wp.ctx.Value("start_time")
	if startTime == nil {
		// Use default if not set
	}

	for _, scanner := range wp.scanners {
		// Check if scanner supports this target type
		supported := false
		for _, t := range scanner.SupportedTypes() {
			if t == job.Target.Type {
				supported = true
				break
			}
		}

		if !supported {
			continue
		}

		// Check if scanner is enabled in config
		if job.Config != nil && len(job.Config.EnabledRules) > 0 {
			enabled := false
			for _, rule := range job.Config.EnabledRules {
				if rule == scanner.Name() {
					enabled = true
					break
				}
			}
			if !enabled {
				continue
			}
		}

		// Check if scanner is disabled
		if job.Config != nil {
			disabled := false
			for _, rule := range job.Config.DisabledRules {
				if rule == scanner.Name() {
					disabled = true
					break
				}
			}
			if disabled {
				continue
			}
		}

		findings, err := scanner.Scan(wp.ctx, job.Target)
		if err != nil {
			result.Error = err
			result.ErrorString = err.Error()
			continue
		}

		result.Findings = append(result.Findings, findings...)
	}

	return result
}

// Submit adds a job to the worker pool queue.
func (wp *WorkerPool) Submit(job Job) {
	select {
	case wp.jobQueue <- job:
	case <-wp.ctx.Done():
	}
}

// SubmitBatch adds multiple jobs to the worker pool queue.
func (wp *WorkerPool) SubmitBatch(jobs []Job) {
	for _, job := range jobs {
		wp.Submit(job)
	}
}

// Results returns the channel for receiving scan results.
func (wp *WorkerPool) Results() <-chan ScanResult {
	return wp.resultChan
}

// Close signals all workers to stop and waits for them to finish.
func (wp *WorkerPool) Close() {
	close(wp.jobQueue)
	wp.wg.Wait()
	close(wp.resultChan)
}

// Stop immediately cancels all workers.
func (wp *WorkerPool) Stop() {
	wp.cancel()
	wp.Close()
}

// Stats returns current worker pool statistics.
func (wp *WorkerPool) Stats() WorkerPoolStats {
	return WorkerPoolStats{
		Workers:        wp.workers,
		ProcessedJobs:  wp.processedCount.Load(),
		Errors:         wp.errorCount.Load(),
		PendingJobs:    int64(len(wp.jobQueue)),
		PendingResults: int64(len(wp.resultChan)),
	}
}

// WorkerPoolStats contains runtime statistics for the worker pool.
type WorkerPoolStats struct {
	Workers        int   `json:"workers"`
	ProcessedJobs  int64 `json:"processed_jobs"`
	Errors         int64 `json:"errors"`
	PendingJobs    int64 `json:"pending_jobs"`
	PendingResults int64 `json:"pending_results"`
}

// ScanEngine orchestrates the entire scanning process.
type ScanEngine struct {
	scanners []Scanner
	config   *ScanConfig
}

// NewScanEngine creates a new scan engine with the provided scanners.
func NewScanEngine(config *ScanConfig, scanners ...Scanner) *ScanEngine {
	if config == nil {
		config = DefaultScanConfig()
	}
	return &ScanEngine{
		scanners: scanners,
		config:   config,
	}
}

// AddScanner registers a new scanner with the engine.
func (e *ScanEngine) AddScanner(s Scanner) {
	e.scanners = append(e.scanners, s)
}

// Scan executes a full scan on the provided targets.
func (e *ScanEngine) Scan(ctx context.Context, targets []Target) ([]ScanResult, ScanSummary) {
	startTime := ctx.Value("start_time")
	if startTime == nil {
		ctx = context.WithValue(ctx, "start_time", startTime)
	}

	pool := NewWorkerPool(ctx, e.config.MaxWorkers, e.scanners)
	pool.Start()

	// Collect results in a separate goroutine
	var results []ScanResult
	var resultsMu sync.Mutex
	done := make(chan struct{})

	go func() {
		for result := range pool.Results() {
			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}
		close(done)
	}()

	// Submit all jobs
	for _, target := range targets {
		pool.Submit(Job{
			Target: target,
			Config: e.config,
		})
	}

	// Signal no more jobs and wait
	pool.Close()
	<-done

	summary := CalculateSummary(results, startTime.(time.Time))
	return results, summary
}

// ScanAsync performs an asynchronous scan, returning results via channel.
func (e *ScanEngine) ScanAsync(ctx context.Context, targets []Target, resultChan chan<- ScanResult) {
	pool := NewWorkerPool(ctx, e.config.MaxWorkers, e.scanners)
	pool.Start()

	go func() {
		for result := range pool.Results() {
			resultChan <- result
		}
		close(resultChan)
	}()

	// Submit jobs asynchronously
	go func() {
		for _, target := range targets {
			pool.Submit(Job{
				Target: target,
				Config: e.config,
			})
		}
		pool.Close()
	}()
}
