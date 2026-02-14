package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/obeginners/antigravity-403-plugin/internal/proxy"
	"gopkg.in/yaml.v3"
)

type pluginFileConfig struct {
	Listen                    *string `yaml:"listen"`
	CLIUpstream               *string `yaml:"cli-upstream"`
	AntigravityUpstream       *string `yaml:"antigravity-upstream"`
	Fingerprint               *string `yaml:"fingerprint"`
	Domains                   *string `yaml:"domains"`
	RequestTimeout            *string `yaml:"request-timeout"`
	DialTimeout               *string `yaml:"dial-timeout"`
	LogCleanupInterval        *string `yaml:"log-cleanup-interval"`
	DisableProxyBypass        *bool   `yaml:"disable-proxy-bypass"`
	DisableH2Pool             *bool   `yaml:"disable-h2-pool"`
	InjectAuthBaseURL         *bool   `yaml:"inject-auth-base-url"`
	InjectBaseURL             *string `yaml:"inject-base-url"`
	ForceAuthRefresh          *bool   `yaml:"force-auth-refresh"`
	AuthDir                   *string `yaml:"auth-dir"`
	SelfCheck                 *bool   `yaml:"self-check"`
	SelfCheckTimeout          *string `yaml:"self-check-timeout"`
	SelfCheckAPIKey           *string `yaml:"self-check-api-key"`
	SelfCheckRecoveryRetries  *int    `yaml:"self-check-recovery-retries"`
	SelfCheckRecoveryInterval *string `yaml:"self-check-recovery-interval"`
}

func main() {
	configPath, configRequired := resolveConfigPathFromArgs(os.Args[1:])
	fileCfg, loadedConfigPath, configLoaded, errCfg := loadPluginConfig(configPath, configRequired)
	if errCfg != nil {
		log.Fatalf("failed to load config: %v", errCfg)
	}

	configPathFlag := flag.String("config", configPath, "path to plugin config file (yaml)")
	listenAddr := flag.String("listen", resolveStringSetting("PLUGIN_LISTEN", fileCfg.Listen, "127.0.0.1:9813"), "plugin listen address")
	cliUpstreamAddr := flag.String("cli-upstream", resolveStringSetting("CLIPROXY_UPSTREAM", fileCfg.CLIUpstream, "http://127.0.0.1:9317"), "official CLIProxyAPI upstream address")
	antigravityUpstreamAddr := flag.String("antigravity-upstream", resolveStringSetting("ANTIGRAVITY_UPSTREAM", fileCfg.AntigravityUpstream, "https://daily-cloudcode-pa.googleapis.com,https://daily-cloudcode-pa.sandbox.googleapis.com"), "antigravity upstream address, supports comma-separated fallback list")
	fingerprint := flag.String("fingerprint", resolveStringSetting("PLUGIN_FINGERPRINT", fileCfg.Fingerprint, "chrome"), "utls fingerprint: chrome|firefox")
	domainList := flag.String("domains", resolveStringSetting("PLUGIN_DOMAINS", fileCfg.Domains, "cloudcode-pa.googleapis.com,daily-cloudcode-pa.googleapis.com,daily-cloudcode-pa.sandbox.googleapis.com"), "comma-separated cloudcode domains")
	requestTimeout := flag.Duration("request-timeout", resolveDurationSetting("PLUGIN_REQUEST_TIMEOUT", fileCfg.RequestTimeout, 90*time.Second), "per-request timeout")
	dialTimeout := flag.Duration("dial-timeout", resolveDurationSetting("PLUGIN_DIAL_TIMEOUT", fileCfg.DialTimeout, 15*time.Second), "dial timeout")
	logCleanupInterval := flag.String("log-cleanup-interval", resolveStringSettingPreserveEmpty("PLUGIN_LOG_CLEANUP_INTERVAL", fileCfg.LogCleanupInterval, ""), "cleanup interval for plugin.log (startup cleanup + periodic runtime cleanup, e.g. 30d, 720h); empty disables cleanup")
	disableProxyBypass := flag.Bool("disable-proxy-bypass", resolveBoolSetting("PLUGIN_DISABLE_PROXY_BYPASS", fileCfg.DisableProxyBypass, false), "disable direct dialing and always use system proxy settings")
	disableH2Pool := flag.Bool("disable-h2-pool", resolveBoolSetting("PLUGIN_DISABLE_H2_POOL", fileCfg.DisableH2Pool, false), "disable http2 connection pooling")
	injectAuthBaseURL := flag.Bool("inject-auth-base-url", resolveBoolSetting("PLUGIN_INJECT_AUTH_BASE_URL", fileCfg.InjectAuthBaseURL, true), "inject local plugin base_url into antigravity auth files")
	injectBaseURL := flag.String("inject-base-url", resolveStringSetting("PLUGIN_INJECT_BASE_URL", fileCfg.InjectBaseURL, ""), "base_url value to inject into antigravity auth files (default: http://<listen>)")
	forceAuthRefresh := flag.Bool("force-auth-refresh", resolveBoolSetting("PLUGIN_FORCE_AUTH_REFRESH", fileCfg.ForceAuthRefresh, false), "force-write antigravity auth files with a reload marker to trigger CLI hot-reload")
	authDir := flag.String("auth-dir", resolveStringSetting("PLUGIN_AUTH_DIR", fileCfg.AuthDir, defaultAuthDir()), "auth directory used by source CLI")
	selfCheck := flag.Bool("self-check", resolveBoolSetting("PLUGIN_SELF_CHECK", fileCfg.SelfCheck, true), "run startup self-check and print diagnostics")
	selfCheckTimeout := flag.Duration("self-check-timeout", resolveDurationSetting("PLUGIN_SELF_CHECK_TIMEOUT", fileCfg.SelfCheckTimeout, 20*time.Second), "timeout for startup self-check")
	selfCheckAPIKey := flag.String("self-check-api-key", resolveStringSettingWithFallbackEnv("PLUGIN_SELF_CHECK_API_KEY", "PLUGIN_CLI_API_KEY", fileCfg.SelfCheckAPIKey, ""), "optional API key used to verify /v1/models on CLI upstream")
	selfCheckRecoveryRetries := flag.Int("self-check-recovery-retries", resolveIntSetting("PLUGIN_SELF_CHECK_RECOVERY_RETRIES", fileCfg.SelfCheckRecoveryRetries, 3), "when gemini_count=0, force auth refresh and retry this many times")
	selfCheckRecoveryInterval := flag.Duration("self-check-recovery-interval", resolveDurationSetting("PLUGIN_SELF_CHECK_RECOVERY_INTERVAL", fileCfg.SelfCheckRecoveryInterval, 2*time.Second), "interval between self-check recovery retries")
	restoreGuard := flag.Bool("restore-guard", false, "internal: wait parent exit and restore injected base_url")
	guardParentPID := flag.Int("guard-parent-pid", 0, "internal: parent plugin PID")
	guardParentStart := flag.String("guard-parent-start", "", "internal: parent plugin creation filetime")
	guardAuthDir := flag.String("guard-auth-dir", "", "internal: auth directory to restore")
	guardManagedBaseURL := flag.String("guard-managed-base-url", "", "internal: managed base_url for restore")
	flag.Parse()

	logRuntime, errLog := setupFileLogging(*logCleanupInterval)
	if errLog != nil {
		log.Fatalf("failed to initialize file logging: %v", errLog)
	}
	defer logRuntime.Close()
	logRuntime.StartPeriodicCleanup()
	currentPID := os.Getpid()

	if *restoreGuard {
		parentStart := uint64(0)
		if parsed, errParse := strconv.ParseUint(strings.TrimSpace(*guardParentStart), 10, 64); errParse == nil {
			parentStart = parsed
		}
		runRestoreGuard(*guardParentPID, parentStart, strings.TrimSpace(*guardAuthDir), strings.TrimSpace(*guardManagedBaseURL))
		return
	}

	if configLoaded {
		log.Printf("config loaded: %s", loadedConfigPath)
	} else {
		log.Printf("config not found: %s (using env/flags/defaults)", strings.TrimSpace(*configPathFlag))
	}
	authPath, errExpand := expandPath(strings.TrimSpace(*authDir))
	if errExpand != nil {
		log.Fatalf("failed to resolve auth-dir: %v", errExpand)
	}

	cfg := proxy.Config{
		ListenAddr:              strings.TrimSpace(*listenAddr),
		CLIUpstreamAddr:         strings.TrimSpace(*cliUpstreamAddr),
		AntigravityUpstreamAddr: strings.TrimSpace(*antigravityUpstreamAddr),
		Fingerprint:             strings.TrimSpace(*fingerprint),
		DomainAllowlist:         splitCSV(*domainList),
		DialTimeout:             *dialTimeout,
		RequestTimeout:          *requestTimeout,
		DisableProxyBypass:      *disableProxyBypass,
		DisableHTTP2Pooling:     *disableH2Pool,
	}

	injectTargetBaseURL := resolveInjectBaseURL(cfg.ListenAddr, strings.TrimSpace(*injectBaseURL))

	if errListen := ensureListenAddrAvailable(cfg.ListenAddr); errListen != nil {
		log.Fatalf("listen preflight failed on %s: %v", cfg.ListenAddr, errListen)
	}

	if *injectAuthBaseURL {
		updated, errInject := injectAntigravityBaseURL(authPath, injectTargetBaseURL, *forceAuthRefresh)
		if errInject != nil {
			log.Fatalf("failed to inject base_url into antigravity auth files: %v", errInject)
		}
		if updated == 0 {
			log.Printf("auth inject: no file updated in %s (no antigravity auth file found)", authPath)
		} else {
			log.Printf("auth inject done: updated %d file(s), base_url=%s, force_auth_refresh=%v", updated, injectTargetBaseURL, *forceAuthRefresh)
		}
		parentStart, errStart := currentProcessCreationTime()
		if errStart != nil {
			log.Printf("restore guard parent-start probe failed: %v", errStart)
		}
		if errGuard := startRestoreGuard(currentPID, parentStart, authPath, injectTargetBaseURL); errGuard != nil {
			log.Printf("restore guard start failed: %v", errGuard)
		} else {
			log.Printf("restore guard started for pid=%d", currentPID)
		}
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		log.Fatalf("plugin init failed: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *injectAuthBaseURL {
		// Keep watching auth-dir so newly added credentials are auto-patched.
		go watchAuthDir(ctx, authPath, injectTargetBaseURL)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("plugin started | listen=%s cli_upstream=%s antigravity_upstream=%s fingerprint=%s", cfg.ListenAddr, cfg.CLIUpstreamAddr, cfg.AntigravityUpstreamAddr, cfg.Fingerprint)
		errCh <- srv.Start()
	}()
	if *selfCheck {
		go runStartupSelfCheck(
			cfg,
			authPath,
			strings.TrimSpace(*selfCheckAPIKey),
			*selfCheckTimeout,
			*injectAuthBaseURL,
			injectTargetBaseURL,
			*forceAuthRefresh,
			*selfCheckRecoveryRetries,
			*selfCheckRecoveryInterval,
		)
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if errShutdown := srv.Shutdown(shutdownCtx); errShutdown != nil {
			log.Printf("plugin shutdown error: %v", errShutdown)
		}
		if *injectAuthBaseURL {
			restored, errRestore := restoreAntigravityBaseURL(authPath, injectTargetBaseURL)
			if errRestore != nil {
				log.Printf("auth restore failed: %v", errRestore)
			} else if restored > 0 {
				log.Printf("auth restore done: restored %d file(s)", restored)
			}
		}
		log.Print("plugin stopped")
	case errRun := <-errCh:
		if errRun != nil && !errors.Is(errRun, context.Canceled) && !errors.Is(errRun, syscall.EINVAL) {
			if *injectAuthBaseURL {
				restored, errRestore := restoreAntigravityBaseURL(authPath, injectTargetBaseURL)
				if errRestore != nil {
					log.Printf("auth restore on runtime error failed: %v", errRestore)
				} else if restored > 0 {
					log.Printf("auth restore on runtime error done: restored %d file(s)", restored)
				}
			}
			log.Fatalf("plugin runtime error: %v", errRun)
		}
	}
}

func resolveConfigPathFromArgs(args []string) (string, bool) {
	configPath := "config.yaml"
	required := false
	if envPath, ok := lookupEnvTrim("PLUGIN_CONFIG"); ok {
		configPath = envPath
		required = true
	}
	if flagPath, ok := extractFlagString(args, "config"); ok {
		configPath = flagPath
		required = true
	}
	return configPath, required
}

func extractFlagString(args []string, name string) (string, bool) {
	shortName := "-" + name
	longName := "--" + name
	shortPrefix := shortName + "="
	longPrefix := longName + "="
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		switch {
		case arg == shortName || arg == longName:
			if i+1 >= len(args) {
				return "", true
			}
			return strings.TrimSpace(args[i+1]), true
		case strings.HasPrefix(arg, shortPrefix):
			return strings.TrimSpace(arg[len(shortPrefix):]), true
		case strings.HasPrefix(arg, longPrefix):
			return strings.TrimSpace(arg[len(longPrefix):]), true
		}
	}
	return "", false
}

func loadPluginConfig(path string, required bool) (pluginFileConfig, string, bool, error) {
	var cfg pluginFileConfig
	path = strings.TrimSpace(path)
	if path == "" {
		if required {
			return cfg, "", false, fmt.Errorf("config path is empty")
		}
		return cfg, "", false, nil
	}

	resolvedPath, err := resolveConfigFilePath(path)
	if err != nil {
		return cfg, "", false, err
	}
	raw, err := os.ReadFile(resolvedPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return cfg, resolvedPath, false, nil
		}
		return cfg, resolvedPath, false, err
	}

	raw = bytes.TrimSpace(stripUTF8BOM(raw))
	if len(raw) == 0 {
		return cfg, resolvedPath, true, nil
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err = decoder.Decode(&cfg); err != nil {
		return cfg, resolvedPath, true, err
	}
	return cfg, resolvedPath, true, nil
}

func resolveConfigFilePath(path string) (string, error) {
	expandedPath, err := expandPath(path)
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(expandedPath) {
		return expandedPath, nil
	}

	var cwd string
	cwd, err = os.Getwd()
	if err == nil {
		cwdCandidate := filepath.Clean(filepath.Join(cwd, expandedPath))
		if _, statErr := os.Stat(cwdCandidate); statErr == nil {
			return cwdCandidate, nil
		}
	}

	exePath, exeErr := os.Executable()
	if exeErr == nil {
		exeCandidate := filepath.Clean(filepath.Join(filepath.Dir(exePath), expandedPath))
		if _, statErr := os.Stat(exeCandidate); statErr == nil {
			return exeCandidate, nil
		}
	}

	if strings.TrimSpace(cwd) != "" {
		return filepath.Clean(filepath.Join(cwd, expandedPath)), nil
	}
	return expandedPath, nil
}

func lookupEnvTrim(key string) (string, bool) {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return "", false
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", false
	}
	return value, true
}

type fileLogRuntime struct {
	file            *os.File
	path            string
	cleanupInterval time.Duration
	cleanupEnabled  bool
	writerMu        sync.Mutex
	stopCh          chan struct{}
	doneCh          chan struct{}
}

type timestampWriter struct {
	writer io.Writer
	mu     *sync.Mutex
}

func (r *fileLogRuntime) Close() {
	if r == nil {
		return
	}
	if r.stopCh != nil {
		close(r.stopCh)
		r.stopCh = nil
		if r.doneCh != nil {
			<-r.doneCh
			r.doneCh = nil
		}
	}
	if r.file == nil {
		return
	}
	r.writerMu.Lock()
	defer r.writerMu.Unlock()
	_ = r.file.Close()
}

func (w *timestampWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w.mu != nil {
		w.mu.Lock()
		defer w.mu.Unlock()
	}

	normalized := bytes.ReplaceAll(p, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalized, []byte("\n"))
	var out bytes.Buffer

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		out.WriteByte('[')
		out.WriteString(time.Now().Format("2006-01-02 15:04:05"))
		out.WriteString("] ")
		out.Write(line)
		out.WriteByte('\n')
	}

	if out.Len() == 0 {
		return len(p), nil
	}
	if _, err := w.writer.Write(out.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}

func setupFileLogging(cleanupRaw string) (*fileLogRuntime, error) {
	baseDir, err := runtimeBaseDir()
	if err != nil {
		return nil, err
	}
	logDir := filepath.Join(baseDir, "logs")
	if err = os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}

	filePath := filepath.Join(logDir, "plugin.log")

	keepDuration, cleanupEnabled, err := parseLogCleanupInterval(cleanupRaw)
	if err != nil {
		return nil, err
	}

	prunedLines := 0
	if cleanupEnabled {
		prunedLines, err = cleanupLogFileByInterval(filePath, keepDuration, time.Now())
		if err != nil {
			return nil, err
		}
	}

	logFile, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	runtime := &fileLogRuntime{
		file:            logFile,
		path:            filePath,
		cleanupInterval: keepDuration,
		cleanupEnabled:  cleanupEnabled,
	}
	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(&timestampWriter{writer: io.MultiWriter(os.Stdout, logFile), mu: &runtime.writerMu})

	if cleanupEnabled {
		log.Printf("file logging enabled | path=%s | cleanup_interval=%s | pruned_lines=%d", filePath, keepDuration.String(), prunedLines)
		return runtime, nil
	}
	log.Printf("file logging enabled | path=%s | cleanup_interval=disabled", filePath)
	return runtime, nil
}

func (r *fileLogRuntime) StartPeriodicCleanup() {
	if r == nil || !r.cleanupEnabled || r.cleanupInterval <= 0 {
		return
	}
	if r.stopCh != nil {
		return
	}

	r.stopCh = make(chan struct{})
	r.doneCh = make(chan struct{})
	interval := r.cleanupInterval

	go func() {
		defer close(r.doneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				prunedLines, err := r.cleanupOnce(time.Now())
				if err != nil {
					log.Printf("periodic log cleanup failed: %v", err)
					continue
				}
				if prunedLines > 0 {
					log.Printf("periodic log cleanup done | interval=%s | pruned_lines=%d", interval.String(), prunedLines)
				}
			case <-r.stopCh:
				return
			}
		}
	}()

	log.Printf("periodic log cleanup enabled | interval=%s", interval.String())
}

func (r *fileLogRuntime) cleanupOnce(now time.Time) (int, error) {
	if r == nil || !r.cleanupEnabled || r.cleanupInterval <= 0 {
		return 0, nil
	}
	r.writerMu.Lock()
	defer r.writerMu.Unlock()
	return cleanupLogFileByInterval(r.path, r.cleanupInterval, now)
}

func runtimeBaseDir() (string, error) {
	exePath, err := os.Executable()
	if err == nil && strings.TrimSpace(exePath) != "" {
		return filepath.Dir(filepath.Clean(exePath)), nil
	}
	return os.Getwd()
}

func parseLogCleanupInterval(raw string) (time.Duration, bool, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false, nil
	}
	parsed, err := parseExtendedDuration(value)
	if err != nil {
		return 0, false, fmt.Errorf("invalid log-cleanup-interval %q: %w", value, err)
	}
	if parsed <= 0 {
		return 0, false, fmt.Errorf("log-cleanup-interval must be > 0 or empty")
	}
	return parsed, true, nil
}

func parseExtendedDuration(raw string) (time.Duration, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return 0, fmt.Errorf("duration is empty")
	}
	if parsed, err := time.ParseDuration(value); err == nil {
		return parsed, nil
	}

	if strings.HasSuffix(value, "\u5929") {
		daysRaw := strings.TrimSpace(strings.TrimSuffix(value, "\u5929"))
		return parseDaysToDuration(daysRaw)
	}
	if strings.HasSuffix(value, "days") {
		daysRaw := strings.TrimSpace(strings.TrimSuffix(value, "days"))
		return parseDaysToDuration(daysRaw)
	}
	if strings.HasSuffix(value, "day") {
		daysRaw := strings.TrimSpace(strings.TrimSuffix(value, "day"))
		return parseDaysToDuration(daysRaw)
	}
	if strings.HasSuffix(value, "d") {
		daysRaw := strings.TrimSpace(strings.TrimSuffix(value, "d"))
		return parseDaysToDuration(daysRaw)
	}

	return 0, fmt.Errorf("unsupported duration format")
}

func parseDaysToDuration(daysRaw string) (time.Duration, error) {
	if daysRaw == "" {
		return 0, fmt.Errorf("days is empty")
	}
	days, err := strconv.ParseFloat(daysRaw, 64)
	if err != nil {
		return 0, err
	}
	if days <= 0 {
		return 0, fmt.Errorf("days must be > 0")
	}
	hours := days * 24
	return time.Duration(hours * float64(time.Hour)), nil
}

func cleanupLogFileByInterval(filePath string, keepDuration time.Duration, now time.Time) (int, error) {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	if len(raw) == 0 {
		return 0, nil
	}

	removed := 0
	cutoff := now.Add(-keepDuration)
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	kept := make([]string, 0, len(lines))

	for _, line := range lines {
		if line == "" {
			continue
		}
		ts, ok := parseTimestampedLogLineTime(line)
		if ok && ts.Before(cutoff) {
			removed++
			continue
		}
		kept = append(kept, line)
	}

	output := strings.Join(kept, "\n")
	if len(kept) > 0 {
		output += "\n"
	}
	if err = os.WriteFile(filePath, []byte(output), 0o644); err != nil {
		return removed, err
	}
	return removed, nil
}

func parseTimestampedLogLineTime(line string) (time.Time, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "[") {
		return time.Time{}, false
	}
	endIdx := strings.Index(line, "]")
	if endIdx <= 1 {
		return time.Time{}, false
	}
	tsRaw := strings.TrimSpace(line[1:endIdx])
	if tsRaw == "" {
		return time.Time{}, false
	}
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", tsRaw, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}
func resolveStringSetting(envKey string, configValue *string, fallback string) string {
	if value, ok := lookupEnvTrim(envKey); ok {
		return value
	}
	if configValue != nil {
		if value := strings.TrimSpace(*configValue); value != "" {
			return value
		}
	}
	return fallback
}

func resolveStringSettingPreserveEmpty(envKey string, configValue *string, fallback string) string {
	if raw, ok := os.LookupEnv(envKey); ok {
		return strings.TrimSpace(raw)
	}
	if configValue != nil {
		return strings.TrimSpace(*configValue)
	}
	return fallback
}

func resolveStringSettingWithFallbackEnv(primaryEnvKey string, fallbackEnvKey string, configValue *string, fallback string) string {
	if value, ok := lookupEnvTrim(primaryEnvKey); ok {
		return value
	}
	if value, ok := lookupEnvTrim(fallbackEnvKey); ok {
		return value
	}
	if configValue != nil {
		if value := strings.TrimSpace(*configValue); value != "" {
			return value
		}
	}
	return fallback
}

func resolveBoolSetting(envKey string, configValue *bool, fallback bool) bool {
	if raw, ok := os.LookupEnv(envKey); ok {
		if parsed, valid := parseBool(raw); valid {
			return parsed
		}
	}
	if configValue != nil {
		return *configValue
	}
	return fallback
}

func resolveDurationSetting(envKey string, configValue *string, fallback time.Duration) time.Duration {
	if value, ok := lookupEnvTrim(envKey); ok {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	if configValue != nil {
		if parsed, err := time.ParseDuration(strings.TrimSpace(*configValue)); err == nil {
			return parsed
		}
	}
	return fallback
}

func resolveIntSetting(envKey string, configValue *int, fallback int) int {
	if value, ok := lookupEnvTrim(envKey); ok {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	if configValue != nil {
		return *configValue
	}
	return fallback
}

func parseBool(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true, true
	case "0", "false", "no", "n", "off":
		return false, true
	default:
		return false, false
	}
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed := strings.TrimSpace(strings.ToLower(v))
	switch parsed {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func resolveInjectBaseURL(listenAddr, override string) string {
	if override != "" {
		return strings.TrimSuffix(override, "/")
	}
	if strings.HasPrefix(strings.ToLower(listenAddr), "http://") || strings.HasPrefix(strings.ToLower(listenAddr), "https://") {
		return strings.TrimSuffix(listenAddr, "/")
	}
	return "http://" + strings.TrimSuffix(listenAddr, "/")
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		item := strings.TrimSpace(strings.ToLower(p))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func mustParseDuration(raw string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return d
}

func mustParseInt(raw string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return v
}

func expandPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("path is empty")
	}
	if strings.HasPrefix(path, "~") {
		home := strings.TrimSpace(os.Getenv("USERPROFILE"))
		if home == "" {
			var err error
			home, err = os.UserHomeDir()
			if err != nil {
				return "", err
			}
		}
		if path == "~" {
			path = home
		} else if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
			path = filepath.Join(home, path[2:])
		}
	}
	return filepath.Clean(path), nil
}

func defaultAuthDir() string {
	if userProfile := strings.TrimSpace(os.Getenv("USERPROFILE")); userProfile != "" {
		return filepath.Join(userProfile, ".cli-proxy-api-src")
	}
	return "~/.cli-proxy-api-src"
}

func ensureListenAddrAvailable(addr string) error {
	listenAddr := strings.TrimSpace(addr)
	if listenAddr == "" {
		return fmt.Errorf("listen address is empty")
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	_ = ln.Close()
	return nil
}

func startRestoreGuard(parentPID int, parentStart uint64, authDir string, managedBaseURL string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	if parentPID <= 0 {
		return fmt.Errorf("invalid parent pid")
	}
	authDir = strings.TrimSpace(authDir)
	if authDir == "" {
		return fmt.Errorf("auth dir is empty")
	}
	managedBaseURL = strings.TrimSpace(managedBaseURL)

	cmd := exec.Command(
		exePath,
		"-restore-guard=true",
		"-guard-parent-pid", strconv.Itoa(parentPID),
		"-guard-parent-start", strconv.FormatUint(parentStart, 10),
		"-guard-auth-dir", authDir,
		"-guard-managed-base-url", managedBaseURL,
		"-log-cleanup-interval", "",
		"-self-check=false",
		"-inject-auth-base-url=false",
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	configureChildProcess(cmd)
	return cmd.Start()
}

func runRestoreGuard(parentPID int, parentStart uint64, authDir string, managedBaseURL string) {
	if parentPID <= 0 {
		log.Printf("restore guard: invalid parent pid %d", parentPID)
		return
	}
	if strings.TrimSpace(authDir) == "" {
		log.Printf("restore guard: empty auth dir")
		return
	}
	resolvedAuthDir, err := expandPath(authDir)
	if err != nil {
		log.Printf("restore guard: resolve auth dir failed: %v", err)
		return
	}

	if err = waitForProcessExit(parentPID, parentStart); err != nil {
		log.Printf("restore guard: wait parent exit failed: %v", err)
		return
	}
	restored, err := restoreAntigravityBaseURL(resolvedAuthDir, managedBaseURL)
	if err != nil {
		log.Printf("restore guard: restore failed: %v", err)
		return
	}
	if restored > 0 {
		log.Printf("restore guard: restored %d file(s) for pid=%d", restored, parentPID)
	}
}

func injectAntigravityBaseURL(authDir string, baseURL string, forceRefresh bool) (int, error) {
	entries, err := os.ReadDir(authDir)
	if err != nil {
		return 0, err
	}
	updated := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(entry.Name()))
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		fullPath := filepath.Join(authDir, entry.Name())
		ok, errSet := setBaseURLInAuthFile(fullPath, baseURL, forceRefresh)
		if errSet != nil {
			log.Printf("auth inject: skip invalid file %s: %v", entry.Name(), errSet)
			continue
		}
		if ok {
			updated++
		}
	}
	return updated, nil
}

func watchAuthDir(ctx context.Context, authDir string, baseURL string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("auth watch: disabled (new watcher failed): %v", err)
		return
	}
	defer watcher.Close()

	if err = watcher.Add(authDir); err != nil {
		log.Printf("auth watch: disabled (watch add failed): %v", err)
		return
	}

	log.Printf("auth watch: started for %s", authDir)
	const debounceWindow = 250 * time.Millisecond
	lastWrite := make(map[string]time.Time)

	for {
		select {
		case <-ctx.Done():
			log.Printf("auth watch: stopped")
			return
		case watchErr, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("auth watch: watcher error: %v", watchErr)
		case evt, ok := <-watcher.Events:
			if !ok {
				return
			}
			if !shouldHandleAuthEvent(evt) {
				continue
			}
			path := filepath.Clean(evt.Name)
			if !strings.EqualFold(filepath.Ext(path), ".json") {
				continue
			}
			now := time.Now()
			if last, exists := lastWrite[path]; exists && now.Sub(last) < debounceWindow {
				continue
			}
			lastWrite[path] = now

			updated, errInject := injectSingleAuthFile(path, baseURL)
			if errInject != nil {
				log.Printf("auth watch: skip %s: %v", filepath.Base(path), errInject)
				continue
			}
			if updated {
				log.Printf("auth watch: injected base_url into %s", filepath.Base(path))
			}
		}
	}
}

func shouldHandleAuthEvent(evt fsnotify.Event) bool {
	return evt.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) != 0
}

func injectSingleAuthFile(path string, baseURL string) (bool, error) {
	const maxAttempts = 4
	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		updated, err := setBaseURLInAuthFile(path, baseURL, false)
		if err == nil {
			return updated, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		lastErr = err
		if !shouldRetryInject(err) || i == maxAttempts-1 {
			break
		}
		time.Sleep(time.Duration(100*(i+1)) * time.Millisecond)
	}
	return false, lastErr
}

func shouldRetryInject(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "unexpected end of json input")
}

func setBaseURLInAuthFile(path string, baseURL string, forceRefresh bool) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	raw = stripUTF8BOM(raw)
	if len(raw) == 0 {
		return false, nil
	}
	var payload map[string]any
	if err = json.Unmarshal(raw, &payload); err != nil {
		return false, err
	}
	typeVal, _ := payload["type"].(string)
	if strings.ToLower(strings.TrimSpace(typeVal)) != "antigravity" {
		return false, nil
	}
	current, _ := payload["base_url"].(string)
	target := strings.TrimSpace(baseURL)
	changed := false
	if normalizeURLForCompare(current) != normalizeURLForCompare(target) {
		payload["base_url"] = target
		changed = true
	}
	if forceRefresh {
		if !changed {
			normalized := target
			if strings.HasSuffix(strings.TrimSpace(current), "/") {
				normalized = strings.TrimSuffix(normalized, "/")
			} else {
				normalized = strings.TrimSuffix(normalized, "/") + "/"
			}
			payload["base_url"] = normalized
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	if err = os.WriteFile(path, out, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

func restoreAntigravityBaseURL(authDir string, managedBaseURL string) (int, error) {
	entries, err := os.ReadDir(authDir)
	if err != nil {
		return 0, err
	}
	restored := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(entry.Name()))
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		fullPath := filepath.Join(authDir, entry.Name())
		ok, errRestore := restoreBaseURLInAuthFile(fullPath, managedBaseURL)
		if errRestore != nil {
			log.Printf("auth restore: skip invalid file %s: %v", entry.Name(), errRestore)
			continue
		}
		if ok {
			restored++
		}
	}
	return restored, nil
}

func restoreBaseURLInAuthFile(path string, managedBaseURL string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	raw = stripUTF8BOM(raw)
	if len(raw) == 0 {
		return false, nil
	}
	var payload map[string]any
	if err = json.Unmarshal(raw, &payload); err != nil {
		return false, err
	}
	typeVal, _ := payload["type"].(string)
	if strings.ToLower(strings.TrimSpace(typeVal)) != "antigravity" {
		return false, nil
	}

	current := strings.TrimSpace(anyToString(payload["base_url"]))
	managed := strings.TrimSpace(managedBaseURL)
	if normalizeURLForCompare(managed) == "" {
		return false, nil
	}
	if normalizeURLForCompare(current) != normalizeURLForCompare(managed) {
		return false, nil
	}

	changed := false
	if _, exists := payload["base_url"]; exists {
		delete(payload, "base_url")
		changed = true
	}
	if !changed {
		return false, nil
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	if err = os.WriteFile(path, out, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

func normalizeURLForCompare(raw string) string {
	value := strings.TrimSpace(raw)
	return strings.TrimSuffix(value, "/")
}

func anyToString(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func runStartupSelfCheck(
	cfg proxy.Config,
	authDir string,
	apiKey string,
	timeout time.Duration,
	injectAuthBaseURL bool,
	injectBaseURL string,
	forceAuthRefresh bool,
	recoveryRetries int,
	recoveryInterval time.Duration,
) {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if recoveryRetries < 0 {
		recoveryRetries = 0
	}
	if recoveryInterval <= 0 {
		recoveryInterval = 2 * time.Second
	}
	log.Printf("[self-check] started")
	if err := selfCheckHealth(cfg, timeout); err != nil {
		log.Printf("[self-check] plugin health check failed: %v", err)
		return
	}
	log.Printf("[self-check] plugin health check ok")

	token, err := readFirstAntigravityAccessToken(authDir)
	if err != nil {
		log.Printf("[self-check] skip upstream check: %v", err)
	} else {
		if err = selfCheckAntigravityUpstream(cfg, token, timeout); err != nil {
			log.Printf("[self-check] upstream fetchAvailableModels failed: %v", err)
		} else {
			log.Printf("[self-check] upstream fetchAvailableModels ok")
		}
	}

	if strings.TrimSpace(apiKey) == "" {
		log.Printf("[self-check] skip CLI model check: no API key provided (use -self-check-api-key)")
		return
	}
	geminiCount, total, err := selfCheckCLIModelList(cfg, apiKey, timeout)
	if err != nil {
		log.Printf("[self-check] CLI /v1/models check failed: %v", err)
		return
	}
	if geminiCount <= 0 {
		log.Printf("[self-check] WARNING: CLI models total=%d, gemini_count=0", total)
		if injectAuthBaseURL && forceAuthRefresh && recoveryRetries > 0 {
			selfCheckRecoverGeminiModel(
				cfg,
				authDir,
				apiKey,
				timeout,
				injectBaseURL,
				recoveryRetries,
				recoveryInterval,
			)
		}
		return
	}
	log.Printf("[self-check] CLI models ok: total=%d gemini_count=%d", total, geminiCount)
}

func selfCheckRecoverGeminiModel(
	cfg proxy.Config,
	authDir string,
	apiKey string,
	timeout time.Duration,
	baseURL string,
	retries int,
	interval time.Duration,
) {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = resolveInjectBaseURL(cfg.ListenAddr, "")
	}
	for i := 1; i <= retries; i++ {
		updated, err := injectAntigravityBaseURL(authDir, baseURL, true)
		if err != nil {
			log.Printf("[self-check] recovery attempt %d/%d failed to refresh auth: %v", i, retries, err)
			continue
		}
		log.Printf("[self-check] recovery attempt %d/%d refreshed auth files: updated=%d", i, retries, updated)
		time.Sleep(interval)
		geminiCount, total, err := selfCheckCLIModelList(cfg, apiKey, timeout)
		if err != nil {
			log.Printf("[self-check] recovery attempt %d/%d models check failed: %v", i, retries, err)
			continue
		}
		if geminiCount > 0 {
			log.Printf("[self-check] recovery success: CLI models total=%d gemini_count=%d", total, geminiCount)
			return
		}
		log.Printf("[self-check] recovery attempt %d/%d still missing gemini (total=%d)", i, retries, total)
	}
	log.Printf("[self-check] recovery exhausted: gemini models are still missing; restart CLI once if needed")
}

func selfCheckHealth(cfg proxy.Config, timeout time.Duration) error {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get("http://" + strings.TrimSpace(cfg.ListenAddr) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func readFirstAntigravityAccessToken(authDir string) (string, error) {
	entries, err := os.ReadDir(authDir)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(entry.Name()))
		if !strings.HasPrefix(name, "antigravity-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(authDir, entry.Name())
		raw, errRead := os.ReadFile(path)
		if errRead != nil {
			continue
		}
		raw = stripUTF8BOM(raw)
		var payload map[string]any
		if errUnmarshal := json.Unmarshal(raw, &payload); errUnmarshal != nil {
			continue
		}
		t, _ := payload["type"].(string)
		if strings.ToLower(strings.TrimSpace(t)) != "antigravity" {
			continue
		}
		at, _ := payload["access_token"].(string)
		if strings.TrimSpace(at) == "" {
			continue
		}
		return strings.TrimSpace(at), nil
	}
	return "", fmt.Errorf("no usable antigravity access_token found in %s", authDir)
}

func selfCheckAntigravityUpstream(cfg proxy.Config, accessToken string, timeout time.Duration) error {
	if strings.TrimSpace(accessToken) == "" {
		return fmt.Errorf("empty access token")
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodPost, "http://"+strings.TrimSpace(cfg.ListenAddr)+"/v1internal:fetchAvailableModels", strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "antigravity")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, summarizeBody(string(body), 400))
	}
	var parsed map[string]any
	if err = json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	modelsRaw, ok := parsed["models"].(map[string]any)
	if !ok || len(modelsRaw) == 0 {
		return fmt.Errorf("models is empty in upstream response")
	}
	return nil
}

func selfCheckCLIModelList(cfg proxy.Config, apiKey string, timeout time.Duration) (geminiCount int, total int, err error) {
	client := &http.Client{Timeout: timeout}
	req, errReq := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.CLIUpstreamAddr, "/")+"/v1/models", nil)
	if errReq != nil {
		return 0, 0, errReq
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	resp, errDo := client.Do(req)
	if errDo != nil {
		return 0, 0, errDo
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, 0, fmt.Errorf("status=%d body=%s", resp.StatusCode, summarizeBody(string(body), 400))
	}
	var payload struct {
		Data []struct {
			ID      string `json:"id"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &payload); err != nil {
		return 0, 0, err
	}
	total = len(payload.Data)
	for _, item := range payload.Data {
		idLower := strings.ToLower(strings.TrimSpace(item.ID))
		ownedBy := strings.ToLower(strings.TrimSpace(item.OwnedBy))
		if strings.HasPrefix(idLower, "gemini") || ownedBy == "antigravity" {
			geminiCount++
		}
	}
	return geminiCount, total, nil
}

func summarizeBody(body string, max int) string {
	body = strings.TrimSpace(body)
	if max <= 0 || len(body) <= max {
		return body
	}
	return body[:max]
}

func stripUTF8BOM(raw []byte) []byte {
	if len(raw) >= 3 && bytes.Equal(raw[:3], []byte{0xEF, 0xBB, 0xBF}) {
		return raw[3:]
	}
	return raw
}
