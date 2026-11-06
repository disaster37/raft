package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// LoadFromFile loads configuration from configFile, applying defaults and
// environment overrides. A missing config file is not an error (environment
// variables and defaults still apply). envPrefix defaults to "RAFT" when
// empty.
func LoadFromFile(configFile string, envPrefix string) (*Config, error) {
	v := viper.New()
	if configFile != "" {
		v.SetConfigFile(configFile)
		v.SetConfigType("yaml")
	}
	if envPrefix == "" {
		envPrefix = "RAFT"
	}
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	RegisterViperDefaults(v, "")

	if configFile != "" {
		if err := v.ReadInConfig(); err != nil {
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("read config file %s: %w", configFile, err)
			}
		}
	}

	cfg := DefaultConfig()
	raw := readRawConfig(configFile)
	if err := DecodeSettings(collectSettings(v, raw), &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	ApplyDefaults(&cfg)
	return &cfg, nil
}

// DecodeSettings decodes a nested settings map into result using weak typing
// and the extended duration parser.
func DecodeSettings(settings map[string]any, result any) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			stringToDurationHookFunc(),
			stringToWeakSliceHookFunc(","),
		),
		Result: result,
	})
	if err != nil {
		return fmt.Errorf("create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return fmt.Errorf("decode settings: %w", err)
	}
	return nil
}

// ParseExtendedDuration parses a duration like time.ParseDuration but also
// accepts day ("d") and week ("w") units, so "7d", "1w", and "1.5d12h" work.
func ParseExtendedDuration(s string) (time.Duration, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	matches := extendedDurationSegmentRE.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		_, err := time.ParseDuration(s)
		return 0, err
	}
	covered := 0
	for _, m := range matches {
		if m[0] != covered {
			_, err := time.ParseDuration(s)
			return 0, err
		}
		covered = m[1]
	}
	if covered != len(s) {
		_, err := time.ParseDuration(s)
		return 0, err
	}
	var total time.Duration
	for _, m := range matches {
		num, unit := s[m[2]:m[3]], s[m[6]:m[7]]
		switch unit {
		case "d", "w":
			f, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, fmt.Errorf("time: invalid duration %q", s)
			}
			unitDur := 24 * time.Hour
			if unit == "w" {
				unitDur = 7 * 24 * time.Hour
			}
			total += time.Duration(f * float64(unitDur))
		default:
			d, err := time.ParseDuration(fmt.Sprintf("%s%s", num, unit))
			if err != nil {
				return 0, err
			}
			total += d
		}
	}
	return total, nil
}

var extendedDurationSegmentRE = regexp.MustCompile(`([+-]?(\d*\.)?\d+)(ns|us|µs|ms|s|m|h|d|w)`)

func stringToDurationHookFunc() mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data any) (any, error) {
		if f.Kind() != reflect.String || t != reflect.TypeOf(time.Duration(0)) {
			return data, nil
		}
		d, err := ParseExtendedDuration(data.(string))
		if err != nil {
			return nil, err
		}
		return d, nil
	}
}

func stringToWeakSliceHookFunc(sep string) mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data any) (any, error) {
		if f.Kind() != reflect.String || t.Kind() != reflect.Slice {
			return data, nil
		}
		raw := data.(string)
		if raw == "" {
			return []string{}, nil
		}
		return strings.Split(raw, sep), nil
	}
}

func readRawConfig(configFile string) map[string]any {
	if configFile == "" {
		return nil
	}
	//nolint:gosec // configFile is an intentional user-provided path
	raw, err := os.ReadFile(configFile) // #nosec G304
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

func collectSettings(v *viper.Viper, rawConfig map[string]any) map[string]any {
	settings := map[string]any{}
	for _, key := range v.AllKeys() {
		val := v.Get(key)
		if val == nil {
			continue
		}
		if _, isMap := val.(map[string]interface{}); isMap {
			continue
		}
		insertSetting(v, settings, key, val, rawConfig)
	}
	return settings
}

func insertSetting(v *viper.Viper, dst map[string]any, key string, val any, rawConfig map[string]any) {
	parts := strings.Split(key, ".")
	cur := dst
	curRaw := rawConfig
	prefix := ""
	i := 0
	for i < len(parts) {
		rest := strings.Join(parts[i:], ".")
		keyPart := exactKeyPrefix(v.Get(prefix), rest)
		if keyPart == "" {
			keyPart = parts[i]
		}
		if curRaw != nil {
			if rawKey := casePreservingKey(curRaw, keyPart); rawKey != "" {
				keyPart = rawKey
			}
		}
		consumed := strings.Split(keyPart, ".")
		if i+len(consumed) >= len(parts) {
			cur[keyPart] = val
			return
		}
		next, ok := cur[keyPart].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[keyPart] = next
		}
		cur = next
		if curRaw != nil {
			if rawNext, ok := curRaw[keyPart].(map[string]any); ok {
				curRaw = rawNext
			} else {
				curRaw = nil
			}
		}
		if prefix == "" {
			prefix = keyPart
		} else {
			prefix = fmt.Sprintf("%s.%s", prefix, keyPart)
		}
		i += len(consumed)
	}
}

func casePreservingKey(m map[string]any, lowerKey string) string {
	for k := range m {
		if strings.EqualFold(k, lowerKey) {
			return k
		}
	}
	return ""
}

func exactKeyPrefix(src any, key string) string {
	m, ok := src.(map[string]any)
	if !ok {
		typed, okTyped := src.(map[string]string)
		if !okTyped {
			return ""
		}
		m = make(map[string]any, len(typed))
		for k, val := range typed {
			m[k] = val
		}
	}
	parts := strings.Split(key, ".")
	for i := len(parts); i >= 1; i-- {
		candidate := strings.Join(parts[:i], ".")
		if _, ok := m[candidate]; ok {
			return candidate
		}
	}
	return ""
}
