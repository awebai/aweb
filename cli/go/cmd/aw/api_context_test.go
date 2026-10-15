package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestCommandAPIContextBudgetAndParent(t *testing.T) {
	for _, tc := range []struct {
		setting string
		budget  time.Duration
	}{{"", 30 * time.Second}, {"45s", 45 * time.Second}, {"150ms", 150 * time.Millisecond}} {
		t.Run(tc.setting, func(t *testing.T) {
			t.Setenv("AWEB_HTTP_TIMEOUT", tc.setting)
			before := time.Now()
			ctx, cancel := commandAPIContext(nil)
			defer cancel()
			after := time.Now()
			deadline, ok := ctx.Deadline()
			if !ok || deadline.Before(before.Add(tc.budget)) || deadline.After(after.Add(tc.budget)) {
				t.Fatalf("deadline %v does not use API budget %s", deadline, tc.budget)
			}
		})
	}
	t.Setenv("AWEB_HTTP_TIMEOUT", "45s")
	parent, stop := context.WithCancel(context.Background())
	cmd := &cobra.Command{}
	cmd.SetContext(parent)
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	stop()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("caller cancellation lost: %v", ctx.Err())
	}
	parent, stop = context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer stop()
	ctx, cancel = commandAPIContext(nil, parent)
	defer cancel()
	got, _ := ctx.Deadline()
	want, _ := parent.Deadline()
	if !got.Equal(want) {
		t.Fatal("configured budget replaced a shorter caller deadline")
	}
	// Existing embedding callers pass both nil and unexecuted Cobra commands.
	for _, cmd := range []*cobra.Command{nil, {}} {
		ctx, cancel := commandAPIContext(cmd)
		if ctx.Err() != nil {
			t.Fatalf("direct invocation context is already invalid: %v", ctx.Err())
		}
		cancel()
	}
}
