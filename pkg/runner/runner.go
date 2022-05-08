package runner

import (
	"context"
	"errors"
	"time"

	"k8s.io/klog/v2"
)

// ErrTimeout is returned when Runner's Run method fails due to a timeout event.
var ErrTimeout = errors.New("runner received timeout")

// Runnable is the interface that wraps the basic Run method.
//
// Run should be implemented by any task intended to be executed by the Runner.
type Runnable interface {
	Run(ctx context.Context) error
}

// The RunnableFunc type is an adapter to allow the use of ordinary functions as Runnable tasks.
// If f is a function with the appropriate signature, RunnableFunc(f) is a Runnable that calls f.
type RunnableFunc func(ctx context.Context) error

// Run calls f()
func (f RunnableFunc) Run(ctx context.Context) error {
	return f(ctx)
}

// Runner is the interface that wraps the basic Run method.
//
// Run executes submitted Runnable tasks.
type Runner interface {
	Run(ctx context.Context, task Runnable) error
}

// New constructs a new ready-to-use Runner for running a Runnable task.
func New() Runner {
	return &runner{
		complete:        make(chan error),
		timeoutDuration: 0,
	}
}

// NewWithTimeout constructs a new ready-to-use Runner with the specified timeout for running a Runnable task.
func NewWithTimeout(d time.Duration) Runner {
	return &runner{
		complete:        make(chan error),
		timeoutDuration: d,
		timeout:         time.After(d),
	}
}

type runner struct {
	// complete channel reports that processing is done
	complete chan error
	// timeout duration
	timeoutDuration time.Duration
	// timeout channel reports that time has run out
	timeout <-chan time.Time
}

// Run runs the specified task and monitors channel events.
func (r *runner) Run(ctx context.Context, task Runnable) (err error) {
	go func() {
		r.complete <- task.Run(ctx)
	}()

	if r.timeoutDuration > 0 {
		err = r.runWithTimeout()
		return
	} else {
		err = r.runAndWaitForever()
		return
	}
}

func (r *runner) runAndWaitForever() (err error) {
	klog.V(3).Info("Running task and waiting forever")
	select {
	// Signaled when processing is done.
	case err := <-r.complete:
		klog.V(3).Infof("Stopping runner on task completion with error: %v", err)
		return err
	}
}

func (r *runner) runWithTimeout() (err error) {
	klog.V(3).Infof("Running task with timeout: %v", r.timeoutDuration)
	select {
	// Signaled when processing is done.
	case err := <-r.complete:
		klog.V(3).Infof("Stopping runner on task completion with error: %v", err)
		return err
	// Signaled when we run out of time.
	case <-r.timeout:
		klog.V(3).Info("Stopping runner on timeout")
		return ErrTimeout
	}
}
