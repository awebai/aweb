package run

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	DefaultInitBasePrompt  = "Coordinate through aweb mail and chat. Prioritize pending communication first, then continue the best available work. Keep teammates informed, make concrete progress, and leave changes in a reviewable state."
	DefaultInitCommsSuffix = "After handling the communication, return to the best available work if more work remains."
)

func InitUserConfig(in io.Reader, out io.Writer, existing UserConfig) error {
	reader := bufio.NewReader(in)
	current, err := ResolveSettings(existing, SettingOverrides{})
	if err != nil {
		return err
	}
	current = applySuggestedInitDefaults(existing, current)

	fmt.Fprintln(out, "Configuring aw run. Press Enter to keep the current value. Enter '-' to clear a string field.")

	basePrompt, err := promptConfigString(reader, out, "base_prompt", current.BasePrompt)
	if err != nil {
		return err
	}
	workSuffix, err := promptConfigString(reader, out, "work_prompt_suffix", current.WorkPromptSuffix)
	if err != nil {
		return err
	}
	commsSuffix, err := promptConfigString(reader, out, "comms_prompt_suffix", current.CommsPromptSuffix)
	if err != nil {
		return err
	}
	waitSeconds, err := promptConfigInt(reader, out, "wait_seconds", current.WaitSeconds)
	if err != nil {
		return err
	}
	idleWaitSeconds, err := promptConfigInt(reader, out, "idle_wait_seconds", current.IdleWaitSeconds)
	if err != nil {
		return err
	}
	cfg := UserConfig{
		BasePrompt:        basePrompt,
		WorkPromptSuffix:  workSuffix,
		CommsPromptSuffix: commsSuffix,
		WaitSeconds:       waitSeconds,
		IdleWaitSeconds:   idleWaitSeconds,
	}
	path, err := WriteUserConfig(cfg)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Wrote %s\n", path)
	return nil
}

func applySuggestedInitDefaults(existing UserConfig, current Settings) Settings {
	if existing.BasePrompt == nil && strings.TrimSpace(current.BasePrompt) == "" {
		current.BasePrompt = DefaultInitBasePrompt
	}
	if existing.CommsPromptSuffix == nil && strings.TrimSpace(current.CommsPromptSuffix) == "" {
		current.CommsPromptSuffix = DefaultInitCommsSuffix
	}
	return current
}

func promptConfigString(reader *bufio.Reader, out io.Writer, key string, current string) (*string, error) {
	label := current
	if strings.TrimSpace(label) == "" {
		label = "(empty)"
	}
	fmt.Fprintf(out, "%s [%s]: ", key, label)

	value, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	value = strings.TrimRight(value, "\r\n")

	switch value {
	case "":
		value = current
	case "-":
		value = ""
	}

	result := value
	return &result, nil
}

func promptConfigInt(reader *bufio.Reader, out io.Writer, key string, current int) (*int, error) {
	fmt.Fprintf(out, "%s [%d]: ", key, current)

	value, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		result := current
		return &result, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be an integer", key)
	}
	if parsed < 0 {
		return nil, fmt.Errorf("%s must be >= 0", key)
	}
	return &parsed, nil
}
