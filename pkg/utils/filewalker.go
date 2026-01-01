// Package utils provides file system utilities for scanning.
package utils

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/security-cli/secscanner/pkg/scanner"
)

// FileWalker provides file system traversal utilities.
type FileWalker struct {
	excludePatterns []string
	includePatterns []string
	maxFileSize     int64
	followSymlinks  bool
}

// NewFileWalker creates a new file walker with the given options.
func NewFileWalker(opts ...FileWalkerOption) *FileWalker {
	fw := &FileWalker{
		maxFileSize:    10 * 1024 * 1024, // 10MB default
		followSymlinks: false,
	}
	for _, opt := range opts {
		opt(fw)
	}
	return fw
}

// FileWalkerOption is a functional option for FileWalker.
type FileWalkerOption func(*FileWalker)

// WithExcludePatterns sets exclude patterns.
func WithExcludePatterns(patterns []string) FileWalkerOption {
	return func(fw *FileWalker) {
		fw.excludePatterns = patterns
	}
}

// WithIncludePatterns sets include patterns.
func WithIncludePatterns(patterns []string) FileWalkerOption {
	return func(fw *FileWalker) {
		fw.includePatterns = patterns
	}
}

// WithMaxFileSize sets the maximum file size to process.
func WithMaxFileSize(size int64) FileWalkerOption {
	return func(fw *FileWalker) {
		fw.maxFileSize = size
	}
}

// WithFollowSymlinks enables or disables following symlinks.
func WithFollowSymlinks(follow bool) FileWalkerOption {
	return func(fw *FileWalker) {
		fw.followSymlinks = follow
	}
}

// Walk traverses the file system and returns targets for scanning.
func (fw *FileWalker) Walk(root string) ([]scanner.Target, error) {
	var targets []scanner.Target

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip files/directories with errors
		}

		// Skip directories
		if d.IsDir() {
			// Check if directory should be excluded
			if fw.shouldExclude(path) {
				return filepath.SkipDir
			}
			return nil
		}

		// Check symlinks
		if d.Type()&fs.ModeSymlink != 0 && !fw.followSymlinks {
			return nil
		}

		// Check exclusion patterns
		if fw.shouldExclude(path) {
			return nil
		}

		// Check inclusion patterns
		if len(fw.includePatterns) > 0 && !fw.shouldInclude(path) {
			return nil
		}

		// Check file size
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > fw.maxFileSize {
			return nil
		}

		// Skip binary files
		if fw.isBinaryFile(path) {
			return nil
		}

		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		targets = append(targets, scanner.Target{
			Path:    path,
			Type:    scanner.TargetTypeFile,
			Content: content,
			Metadata: map[string]string{
				"size":      formatSize(info.Size()),
				"extension": filepath.Ext(path),
			},
		})

		return nil
	})

	return targets, err
}

// shouldExclude checks if a path matches any exclude pattern.
func (fw *FileWalker) shouldExclude(path string) bool {
	// Default exclusions
	defaultExclusions := []string{
		".git",
		".svn",
		".hg",
		"node_modules",
		"vendor",
		"__pycache__",
		".venv",
		"venv",
		".idea",
		".vscode",
		"dist",
		"build",
		"target",
		".terraform",
	}

	baseName := filepath.Base(path)
	for _, excl := range defaultExclusions {
		if baseName == excl {
			return true
		}
	}

	for _, pattern := range fw.excludePatterns {
		matched, err := matchGlob(pattern, path)
		if err == nil && matched {
			return true
		}
	}

	return false
}

// shouldInclude checks if a path matches any include pattern.
func (fw *FileWalker) shouldInclude(path string) bool {
	for _, pattern := range fw.includePatterns {
		matched, err := matchGlob(pattern, path)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// isBinaryFile checks if a file is likely binary.
func (fw *FileWalker) isBinaryFile(path string) bool {
	binaryExtensions := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".dat": true, ".db": true, ".sqlite": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".bmp": true, ".ico": true, ".webp": true, ".svg": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
		".pdf": true, ".doc": true, ".docx": true, ".xls": true,
		".xlsx": true, ".ppt": true, ".pptx": true,
		".zip": true, ".tar": true, ".gz": true, ".rar": true,
		".7z": true, ".bz2": true, ".xz": true,
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
		".lock": true, ".sum": true,
	}

	ext := strings.ToLower(filepath.Ext(path))
	return binaryExtensions[ext]
}

// matchGlob performs glob matching supporting ** for recursive matching.
func matchGlob(pattern, path string) (bool, error) {
	// Normalize separators
	pattern = filepath.ToSlash(pattern)
	path = filepath.ToSlash(path)

	// Handle ** for recursive matching
	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := strings.TrimSuffix(parts[0], "/")
			suffix := strings.TrimPrefix(parts[1], "/")

			// Check prefix match
			if prefix != "" && !strings.HasPrefix(path, prefix) {
				return false, nil
			}

			// Check suffix match
			if suffix != "" {
				return filepath.Match(suffix, filepath.Base(path))
			}
			return true, nil
		}
	}

	// Standard glob matching
	return filepath.Match(pattern, filepath.Base(path))
}

// formatSize formats a file size for display.
func formatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
