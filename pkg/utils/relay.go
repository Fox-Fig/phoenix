package utils

import (
	"io"
	"sync"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 128*1024) // 128KB buffer for high throughput
		return &b
	},
}

// Relay copies data bidirectionally between two connections.
// It uses a 128KB buffer pool to drastically reduce syscalls and flush overhead
// for high-throughput proxy tunnels, without allocating memory on every connection.
// Returns the first error encountered, or nil if both finish with EOF.
func Relay(left, right io.ReadWriteCloser) error {
	var wg sync.WaitGroup
	wg.Add(2)

	var firstErr error
	var once sync.Once

	go func() {
		defer wg.Done()
		buf := bufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(right, left, *buf)
		bufPool.Put(buf)
		
		if err != nil {
			once.Do(func() { firstErr = err })
		}
		
		// Aggressively close to unblock the other copy direction
		left.Close()
		right.Close()
	}()

	go func() {
		defer wg.Done()
		buf := bufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(left, right, *buf)
		bufPool.Put(buf)
		
		if err != nil {
			once.Do(func() { firstErr = err })
		}
		
		left.Close()
		right.Close()
	}()

	wg.Wait()
	return firstErr
}
