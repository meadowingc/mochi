package lifecycle

import (
	"context"
	"sync"
	"time"
)

type Group struct {
	mu      sync.Mutex
	active  int
	changed chan struct{}
}

var Background Group

func (g *Group) Go(fn func()) {
	g.mu.Lock()
	g.active++
	g.mu.Unlock()
	go func() {
		defer func() {
			g.mu.Lock()
			g.active--
			if g.changed != nil {
				close(g.changed)
				g.changed = nil
			}
			g.mu.Unlock()
		}()
		fn()
	}()
}

func (g *Group) Wait(ctx context.Context) error {
	for {
		g.mu.Lock()
		if g.active == 0 {
			g.mu.Unlock()
			return nil
		}
		if g.changed == nil {
			g.changed = make(chan struct{})
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func RunPeriodic(ctx context.Context, interval, delay time.Duration, fn func()) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		fn()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
