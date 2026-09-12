package agent

import (
	"context"
	"errors"
	"net"
	"sync"
)

const maxAgentConnections = 64

// ServeListener owns all accepted connections until cancellation. One Protected
// instance shares keys across clients, but binding state belongs to each client.
func ServeListener(ctx context.Context, listener net.Listener, protected *Protected) error {
	ctx, cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	defer func() {
		cancel()
		listener.Close()
		mu.Lock()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	}()
	go func() {
		<-ctx.Done()
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for conn := range connections {
			conn.Close()
		}
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		mu.Lock()
		if ctx.Err() != nil {
			mu.Unlock()
			conn.Close()
			return nil
		}
		if len(connections) >= maxAgentConnections {
			mu.Unlock()
			conn.Close()
			continue
		}
		connections[conn] = struct{}{}
		mu.Unlock()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer conn.Close()
			defer func() { mu.Lock(); delete(connections, conn); mu.Unlock() }()
			_ = protected.Serve(ctx, conn)
		}()
	}
}
