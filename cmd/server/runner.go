package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type Runner struct {
	shutdownTimeout time.Duration
	logger          *zap.Logger
}

func NewRunner(shutdownTimeout time.Duration, logger *zap.Logger) *Runner {
	return &Runner{
		shutdownTimeout: shutdownTimeout,
		logger:          logger,
	}
}

// RunnableTask represents a task that can be run and shutdown with separate contexts.
type RunnableTask struct {
	Run      func(context.Context) error
	Shutdown func(context.Context)
}

func (r *Runner) RunAndHandleShutdown(ctx context.Context, tasks ...RunnableTask) error {
	if len(tasks) == 0 {
		return nil
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errChan := make(chan error, len(tasks))
	done := make(chan struct{})

	r.startTasks(taskCtx, tasks, errChan, done)

	returnErr := r.waitForShutdownSignal(ctx, errChan, sigChan, done, cancel)

	r.performGracefulShutdown(tasks, done)

	return returnErr
}

func (r *Runner) startTasks(taskCtx context.Context, tasks []RunnableTask, errChan chan error, done chan struct{}) {
	var wg sync.WaitGroup
	wg.Add(len(tasks))

	for _, task := range tasks {
		runFunc := task.Run

		go func() {
			defer wg.Done()

			if err := runFunc(taskCtx); err != nil {
				if err != context.Canceled && taskCtx.Err() == nil {
					r.logger.Error("Error received from background component", zap.Error(err))
					select {
					case errChan <- fmt.Errorf("task failed: %w", err):
					default:
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(done)
	}()
}

// waitForShutdownSignal waits for an error, signal, context cancellation, or task completion
func (r *Runner) waitForShutdownSignal(ctx context.Context, errChan chan error, sigChan chan os.Signal, done chan struct{}, cancel context.CancelFunc) error {
	var returnErr error

	select {
	case err := <-errChan:
		returnErr = err
	case sig := <-sigChan:
		r.logger.Info("Signal caught", zap.String("signal", sig.String()))
	case <-ctx.Done():
		r.logger.Info("Context cancelled, initiating shutdown")
	case <-done:
		return nil
	}

	cancel()
	return returnErr
}

func (r *Runner) performGracefulShutdown(tasks []RunnableTask, done chan struct{}) {
	r.logger.Info("Initiating graceful shutdown")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), r.shutdownTimeout)
	defer shutdownCancel()

	for _, task := range tasks {
		if task.Shutdown != nil {
			task.Shutdown(shutdownCtx)
		}
	}

	// Wait for all tasks to complete
	shutdownTimer := time.NewTimer(r.shutdownTimeout)
	defer shutdownTimer.Stop()

	select {
	case <-done:
		r.logger.Info("All tasks shut down gracefully")
	case <-shutdownTimer.C:
		r.logger.Error("Shutdown timeout exceeded")
	}
}
