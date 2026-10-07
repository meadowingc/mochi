package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitIncludesChildTasksAndNeverClosesAcceptedWork(t *testing.T) {
	var group Group
	parent, child, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	group.Go(func() {
		close(parent)
		<-release
		group.Go(func() { <-child })
	})
	<-parent
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := group.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked accepted work: %v", err)
	}
	close(release)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel2()
	if err := group.Wait(ctx2); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("child task was not retained: %v", err)
	}
	close(child)
	if err := group.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPeriodicCancellationStopsPendingStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	RunPeriodic(ctx, time.Hour, time.Hour, func() { called = true })
	if called {
		t.Fatal("cancelled scheduler ran a job")
	}
}

func TestPeriodicCancellationDrainsCurrentJob(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		RunPeriodic(ctx, time.Hour, 0, func() { close(entered); <-release })
		close(done)
	}()
	<-entered
	cancel()
	select {
	case <-done:
		t.Fatal("scheduler abandoned its current job")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after draining")
	}
}
