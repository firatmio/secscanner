// Package utils provides progress tracking utilities.
package utils

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/schollz/progressbar/v3"
)

// Progress tracks scanning progress.
type Progress struct {
	total     int64
	current   atomic.Int64
	startTime time.Time
	bar       *progressbar.ProgressBar
	enabled   bool
	writer    io.Writer
}

// NewProgress creates a new progress tracker.
func NewProgress(total int, enabled bool, writer io.Writer) *Progress {
	p := &Progress{
		total:     int64(total),
		startTime: time.Now(),
		enabled:   enabled,
		writer:    writer,
	}

	if enabled && total > 0 {
		p.bar = progressbar.NewOptions64(
			int64(total),
			progressbar.OptionSetWriter(writer),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowBytes(false),
			progressbar.OptionSetWidth(40),
			progressbar.OptionSetDescription("[cyan]🔍 Scanning...[reset]"),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]█[reset]",
				SaucerHead:    "[green]▓[reset]",
				SaucerPadding: "░",
				BarStart:      "[",
				BarEnd:        "]",
			}),
			progressbar.OptionOnCompletion(func() {
				fmt.Fprintln(writer)
			}),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetItsString("files"),
		)
	}

	return p
}

// Increment advances the progress by one.
func (p *Progress) Increment() {
	p.current.Add(1)
	if p.enabled && p.bar != nil {
		p.bar.Add(1)
	}
}

// IncrementBy advances the progress by n.
func (p *Progress) IncrementBy(n int) {
	p.current.Add(int64(n))
	if p.enabled && p.bar != nil {
		p.bar.Add(n)
	}
}

// Current returns the current progress count.
func (p *Progress) Current() int64 {
	return p.current.Load()
}

// Total returns the total count.
func (p *Progress) Total() int64 {
	return p.total
}

// Elapsed returns the elapsed time.
func (p *Progress) Elapsed() time.Duration {
	return time.Since(p.startTime)
}

// Rate returns the processing rate (items per second).
func (p *Progress) Rate() float64 {
	elapsed := p.Elapsed().Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(p.current.Load()) / elapsed
}

// Percentage returns the completion percentage.
func (p *Progress) Percentage() float64 {
	if p.total == 0 {
		return 100
	}
	return float64(p.current.Load()) / float64(p.total) * 100
}

// Finish marks the progress as complete.
func (p *Progress) Finish() {
	if p.enabled && p.bar != nil {
		p.bar.Finish()
	}
}

// SetDescription updates the progress description.
func (p *Progress) SetDescription(desc string) {
	if p.enabled && p.bar != nil {
		p.bar.Describe(desc)
	}
}

// Spinner provides an indeterminate progress indicator.
type Spinner struct {
	frames  []string
	current int
	message string
	running bool
	done    chan struct{}
	writer  io.Writer
}

// NewSpinner creates a new spinner.
func NewSpinner(message string, writer io.Writer) *Spinner {
	return &Spinner{
		frames:  []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		message: message,
		done:    make(chan struct{}),
		writer:  writer,
	}
}

// Start begins the spinner animation.
func (s *Spinner) Start() {
	s.running = true
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				fmt.Fprintf(s.writer, "\r%s %s", s.frames[s.current], s.message)
				s.current = (s.current + 1) % len(s.frames)
			}
		}
	}()
}

// Stop halts the spinner animation.
func (s *Spinner) Stop() {
	if s.running {
		s.running = false
		close(s.done)
		fmt.Fprintln(s.writer, "\r") // Clear the line
	}
}

// Success stops the spinner with a success message.
func (s *Spinner) Success(message string) {
	s.Stop()
	fmt.Fprintf(s.writer, "\r✅ %s\n", message)
}

// Error stops the spinner with an error message.
func (s *Spinner) Error(message string) {
	s.Stop()
	fmt.Fprintf(s.writer, "\r❌ %s\n", message)
}
