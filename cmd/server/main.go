package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Busnes-app/ky-primitives/applysetup"
	"github.com/Busnes-app/ky-primitives/password"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky_server_base/internal/api"
	"github.com/Busnes-app/ky_server_base/internal/backup"
	"github.com/Busnes-app/ky_server_base/internal/config"
	"github.com/Busnes-app/ky_server_base/internal/crypto"
	"github.com/Busnes-app/ky_server_base/internal/store"
	"golang.org/x/term"
)

// appVersion is what the capsule manifest records for this build.
const appVersion = config.AppVersion

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "apply-setup":
			if err := runInstaller(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "init-admin":
			runInitAdmin(os.Args[2:])
			return
		case "backup-drill":
			runBackupDrill(os.Args[2:])
			return
		case "export-capsule":
			runExportCapsule(os.Args[2:])
			return
		case "deposit":
			runDeposit(os.Args[2:])
			return
		case "restore":
			runRestore(os.Args[2:])
			return
		case "invalidate-grants":
			runInvalidateGrants(os.Args[2:])
			return
		case "restore-attachments":
			runRestoreAttachments(os.Args[2:])
			return
		case "version":
			fmt.Printf("kymessages %s\n", appVersion)
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
			os.Exit(2)
		}
	}

	runServer()
}

// shutdownTimeout drains in-flight HTTP requests. Short on purpose: it is spent before the
// backup wait below, and both must fit inside the deployment's stop_grace_period.
const shutdownTimeout = 5 * time.Second

// backupWaitTimeout bounds the wait for detached backup work. recoveryclient caps one deposit
// at 15 minutes (its uploadTimeout, for a container of at most capsule.MaxContainerBytes,
// 384 MiB), and five more minutes cover sealing and the local copy. docker-compose.yml's
// stop_grace_period must exceed shutdownTimeout + backupWaitTimeout, and
// TestComposeGracePeriodCoversTheShutdownBudget holds them in step.
const backupWaitTimeout = 20 * time.Minute

func runServer() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	if cfg.Tenancy.IsMultiTenant() && strings.TrimSpace(os.Getenv("KY_ATTACHMENTS_MAX_TOTAL_BYTES")) != "" {
		log.Printf("[ATTACHMENTS] KY_ATTACHMENTS_MAX_TOTAL_BYTES is ignored in multi-tenant mode: each org's storage pool (KyIdentity) limits its attachments")
	}
	if cfg.Backup.AllowPrivateRecovery {
		log.Printf("[BACKUP] KY_BACKUP_ALLOW_PRIVATE_RECOVERY is on: RFC1918 and CGNAT destinations admitted; loopback, link-local and other reserved addresses remain refused (HTTPS still required)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database (%s): %v", cfg.Database.Driver, err)
	}
	defer st.Close()
	if err := api.EnsureTenancyMode(ctx, st, cfg.Tenancy); err != nil {
		log.Fatalf("Tenancy mode check failed: %v", err)
	}
	if err := loadInstallerConfiguration(ctx, cfg, st); err != nil {
		log.Fatalf("Installer configuration unavailable: %v", err)
	}

	if err := bootstrapAdmin(ctx, st, cfg.Security.AdminUsername, os.Getenv("KY_ADMIN_PASSWORD")); err != nil {
		log.Fatalf("Failed to create bootstrap admin: %v", err)
	}

	srv := api.NewServer(cfg, st)
	if err := srv.BlobsError(); err != nil {
		log.Fatalf("Failed to initialize attachment storage: %v", err)
	}
	if cfg.Tenancy.IsMultiTenant() {
		// Before serving: re-read KyIdentity's org and erased lists (a restore may have undone
		// deletions), or serve only on a sync the database records from the last 24 hours.
		sctx, scancel := context.WithTimeout(ctx, time.Minute)
		err := srv.StartupTenancySync(sctx)
		scancel()
		if err != nil {
			log.Fatalf("Tenancy sync failed: %v", err)
		}
	}
	chatBusDone := make(chan struct{})
	go func() {
		defer close(chatBusDone)
		_ = srv.RunChatBus(ctx)
	}()
	backupDone := make(chan struct{})
	go backupLoop(ctx, cfg, st, backupDone)
	gate := jobGate(everyReplica)
	if cfg.Tenancy.IsMultiTenant() {
		gate = leasedJobs(st)
	}
	maintenanceDone := make(chan struct{})
	go func() {
		agentsDone := make(chan struct{})
		go agentExpiryLoop(ctx, srv.ExpireIdleAgents, gate, agentsDone)
		attachmentsDone := make(chan struct{})
		go attachmentSweepLoop(ctx, srv.SweepOrphanAttachments, gate, attachmentsDone)
		poolDone, syncDone, purgeDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
		if cfg.Tenancy.IsMultiTenant() {
			go poolLoop(ctx, srv.RefreshPool, gate, poolDone)
			go leasedLoop(ctx, "tenancy_sync", 5*time.Minute, gate, func(ctx context.Context, _ func() bool) error {
				return srv.SyncTenancy(ctx, time.Now())
			}, syncDone)
			go leasedLoop(ctx, "org_purge", 5*time.Minute, gate, srv.PurgeDeletedOrgs, purgeDone)
		} else {
			close(poolDone)
			close(syncDone)
			close(purgeDone)
		}
		pairingsDone := make(chan struct{})
		maintenanceLoop(ctx, st, gate, cfg.Tenancy.IsMultiTenant(), pairingsDone)
		<-agentsDone
		<-attachmentsDone
		<-poolDone
		<-syncDone
		<-purgeDone
		close(maintenanceDone)
	}()
	backgroundDone := make(chan struct{})
	go func() { defer close(backgroundDone); <-backupDone; <-maintenanceDone; <-chatBusDone }()

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      srv,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Graceful shutdown channel
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	socket, err := config.InstallerSocket(cfg.Database.DataDir)
	if err != nil {
		log.Fatal(err)
	}
	closeInstaller, err := applysetup.StartLocal(ctx, socket, srv.ApplyInstaller, func() {
		select {
		case stop <- syscall.SIGTERM:
		default:
		}
	})
	if err != nil {
		log.Fatalf("Installer IPC: %v", err)
	}
	defer closeInstaller()

	srv.StartSuitePairs(ctx)
	go func() {
		log.Printf("[KYMESSAGES] %s listening on http://%s (DB: %s)", cfg.Server.AppName, addr, cfg.Database.Driver)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-stop
	log.Println("[KYMESSAGES] Shutting down gracefully...")
	srv.CloseChat()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	cancel()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), backupWaitTimeout)
	defer waitCancel()
	waitForBackupWork(waitCtx, backgroundDone, srv.WaitDetached)
	log.Println("[KYMESSAGES] Server stopped")
}

// waitForBackupWork blocks until the background loops (backup scheduler, maintenance and
// agent idle-expiry sweeps) and every detached handler have finished,
// or until ctx expires. Backup work ignores cancellation once bytes are moving: the scheduler's
// run, and the pair, pin-key and deposit handlers, all detach from their caller; export and drill
// run for minutes under their own write deadlines. They are waited
// out before the store closes, or they write into a closed store -- a key pinned on disk with no
// row recording it, or a capsule at KyRecovery with no receipt this side.
//
// Both waits start before either blocks, and both are bounded by the one context rather than a
// timer channel: a timer channel delivers its value once, so whichever wait consumed it would
// leave the other unbounded -- exactly the stuck-deposit case this is written for. Starting them
// together matters as much: waited one after the other, a hung scheduled deposit spends the whole
// budget on its own and the handler wait is read only once the deadline has already passed,
// giving a live detached handler no time at all. Past the deadline the work is abandoned and said
// so; a SIGKILL would have been silent.
func waitForBackupWork(ctx context.Context, backgroundDone <-chan struct{}, waitDetached func()) {
	handlersDone := make(chan struct{})
	go func() { defer close(handlersDone); waitDetached() }()

	select {
	case <-backgroundDone:
	default:
		log.Println("[KYMESSAGES] waiting for scheduled backup or maintenance sweep in flight...")
		select {
		case <-backgroundDone:
		case <-ctx.Done():
			log.Printf("[KYMESSAGES] abandoning background work still running after %s; a backup receipt may be unrecorded", backupWaitTimeout)
		}
	}
	select {
	case <-handlersDone:
	case <-ctx.Done():
		log.Printf("[KYMESSAGES] abandoning a detached backup handler still running after %s; its writes may be unrecorded", backupWaitTimeout)
	}
}

// runBackup is recoveryclient.Run for the server capsule; tests replace it.
var runBackup = func(ctx context.Context, cfg *config.Config, rc recoveryclient.RunConfig, s recoveryclient.Settings, client recoveryclient.Depositor) (recoveryclient.Result, error) {
	return recoveryclient.Run(ctx, rc, s, func() (recoveryclient.Payload, error) { return backup.CollectForRun(ctx, cfg, s, appVersion) }, client)
}

// backupLoop polls the admin's schedule once a minute; a change in the UI needs no restart
// and a restart never loses its place, the last attempt is in the database. The wait honours
// shutdown; the run does not, and done is closed only once the loop is between runs, so
// SIGTERM cannot land between KyRecovery storing a capsule and the receipt being written.
func backupLoop(ctx context.Context, cfg *config.Config, st store.Store, done chan<- struct{}) {
	defer close(done)
	if cfg.Tenancy.IsMultiTenant() {
		log.Printf("[BACKUP] scheduler off: %s", backup.MultiTenantOff)
		return
	}
	// Run never gets far enough to stamp the attempt on a RunConfig failure, so retrying
	// would log and audit it every tick forever.
	// The status route reports the same failure as scheduler_error; this row is the trail.
	rc, err := backup.RunConfig(cfg, appVersion)
	if err != nil {
		log.Printf("[BACKUP] scheduler disabled: %v", err)
		_ = st.Audit().LogAudit(context.WithoutCancel(ctx), &store.AuditRecord{UserID: "system", Action: schedulerAction,
			Details: api.AuditDetails(map[string]any{"outcome": "failure", "error": "scheduler disabled: " + err.Error()})})
		return
	}
	client := recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.Backup.AllowPrivateRecovery})
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		backupTick(ctx, cfg, st, rc, client)
	}
}

// backupTick runs the server capsule if due. A run that finds the library lock held (an admin
// run) is left unstamped and so still due; the next tick retries it.
func backupTick(ctx context.Context, cfg *config.Config, st store.Store, rc recoveryclient.RunConfig, client recoveryclient.Depositor) {
	if ctx.Err() != nil {
		return // shutdown: the select may still have picked the ticker
	}
	runCtx := context.WithoutCancel(ctx)
	settings := backup.Settings(runCtx, st.Settings())
	next, on, err := recoveryclient.NextRun(cfg.Backup.DepositInterval, settings)
	if err != nil {
		log.Printf("[BACKUP] schedule unreadable: %s", recoveryclient.AuditSafe(err.Error()))
		return
	}
	if !on || time.Now().Before(next) {
		return
	}
	// A cron `kymessages deposit` is another process, which the lib's run lock does not see.
	// Busy leaves the run unstamped, so the next tick retries.
	unlock, err := backup.Lock(cfg.Database.DataDir)
	if err != nil {
		log.Printf("[BACKUP] %s; retrying next tick", recoveryclient.AuditSafe(err.Error()))
		return
	}
	defer unlock()
	res, err := runBackup(runCtx, cfg, rc, settings, client)
	if errors.Is(err, recoveryclient.ErrNotPaired) || errors.Is(err, recoveryclient.ErrNoDestination) {
		return // never configured; nothing to report
	}
	if errors.Is(err, recoveryclient.ErrInProgress) {
		log.Println("[BACKUP] another run is in progress; retrying next tick")
		return
	}
	recordRun(runCtx, st, "system", backupRunAction, res, err)
	if err == nil {
		mirrorAttachments(runCtx, cfg)
	}
}

func mirrorAttachments(ctx context.Context, cfg *config.Config) {
	mres, merr := backup.MirrorAttachments(ctx, cfg)
	if merr != nil {
		log.Printf("[BACKUP] attachment mirror sync warning: %s", recoveryclient.AuditSafe(merr.Error()))
		return
	}
	if mres.KeyMissing {
		log.Printf("[BACKUP] attachment mirror waits for the next backup: its key is sealed into that capsule first")
		return
	}
	if mres.PruneSkipped {
		log.Printf("[BACKUP] attachment mirror prune skipped: live attachments directory is empty while mirror holds %d encrypted blob(s) (run restore-attachments if restoring)", mres.MirrorBlobs)
		return
	}
	if mres.Copied > 0 || mres.Pruned > 0 || mres.Expired > 0 {
		log.Printf("[BACKUP] attachment mirror synced: copied=%d skipped=%d pruned=%d expired=%d", mres.Copied, mres.Skipped, mres.Pruned, mres.Expired)
	}
}

const (
	backupRunAction = "admin.backup_run"
	schedulerAction = "admin.backup_scheduler"
)

// recordRun audits one run the same way the admin route does, under the actor that started it.
func recordRun(ctx context.Context, st store.Store, actor, action string, res recoveryclient.Result, err error) {
	_, outcome, details := recoveryclient.Outcome(res, err)
	details["outcome"] = outcome
	_ = st.Audit().LogAudit(ctx, &store.AuditRecord{UserID: actor, Action: action,
		Resource: res.Manifest.CapsuleID, Details: api.AuditDetails(details)})
	if err != nil {
		log.Printf("[BACKUP] %s: %s", actor, recoveryclient.AuditSafe(err.Error()))
		return
	}
	log.Printf("[BACKUP] %s: capsule %s (%d bytes) local=%q deposited=%t", actor, res.Manifest.CapsuleID, res.SizeBytes, res.LocalPath, res.Receipt != nil)
}

// parseNoArgs refuses every flag and positional argument: these commands take none.
func parseNoArgs(name string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { fmt.Fprintf(out, "Usage: kymessages %s\n", name) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

func mustParseNoArgs(name string, args []string) {
	if err := parseNoArgs(name, args, os.Stderr); err != nil {
		os.Exit(2)
	}
}

// runDeposit seals and delivers one capsule now, for cron or an operator at a shell.
func runDeposit(args []string) {
	mustParseNoArgs("deposit", args)
	ctx := context.Background()
	cfg, st, err := openForSeal(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	rc, err := backup.RunConfig(cfg, appVersion)
	if err != nil {
		log.Fatalf("Backup: %v", err)
	}
	client := recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.Backup.AllowPrivateRecovery})
	// The server's scheduler may be running one now; backup.lock serializes the two processes.
	unlock := mustLock(cfg)
	defer unlock()
	res, err := runBackup(ctx, cfg, rc, backup.Settings(ctx, st.Settings()), client)
	recordRun(ctx, st, "cli", backupRunAction, res, err)
	if err != nil {
		log.Fatalf("Backup: %v", err)
	}
	mirrorAttachments(ctx, cfg)
	if res.Receipt != nil {
		log.Printf("✓ Capsule %s deposited at %s; digest %s", res.Manifest.CapsuleID, res.Receipt.DepositedAt.Format(time.RFC3339), res.Receipt.Digest)
	}
}

// bootstrapAdmin creates the local admin on an empty database, named by KY_ADMIN_USERNAME. A
// blank password is generated and logged once; either way it must be replaced at first sign-in.
func bootstrapAdmin(ctx context.Context, st store.Store, username, adminPass string) error {
	// A failed count is not an empty database: bootstrapping on it would add a second admin
	// and log its password.
	count, err := st.Users().CountUsers(ctx)
	if err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if count != 0 {
		return nil
	}
	if adminPass == "" {
		adminPass = crypto.RandomHex(12)
		log.Printf("[SECURITY] Initial bootstrap: Created admin account. Username: %s | Password: %s", username, adminPass)
	}
	hash, err := password.Hash(adminPass)
	if err != nil {
		return err
	}
	return st.Users().CreateUser(ctx, &store.User{
		ID:                 fmt.Sprintf("usr_%s", crypto.RandomHex(12)),
		Username:           username,
		DisplayName:        "Administrator",
		PasswordHash:       hash,
		Role:               "admin",
		Status:             "active",
		SSOProvider:        "local",
		MustChangePassword: true,
	})
}

// runInvalidateGrants is the multi-mode restore step `restore` runs for a capsule: a database
// restored by PostgreSQL tooling still holds grants revoked after its restore point. Run it with
// every replica stopped.
func runInvalidateGrants(args []string) {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "Usage: kymessages invalidate-grants (with every replica stopped)")
		os.Exit(2)
	}
	cfg, err := config.LoadForMaintenance()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("DB error: %v", err)
	}
	if err := errors.Join(st.InvalidateRestoredGrants(ctx), st.Close()); err != nil {
		log.Fatalf("Invalidating restored grants: %v", err)
	}
	fmt.Println("Sessions, challenges, pairings, push subscriptions, guest sessions, active calls and bot tokens invalidated.")
}

func runInitAdmin(args []string) {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	fs := flag.NewFlagSet("init-admin", flag.ExitOnError)
	username := fs.String("username", cfg.Security.AdminUsername, "Admin username (default KY_ADMIN_USERNAME)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: kymessages init-admin [-username <name>]\n\n"+
			"The password (at least 12 characters) is read from stdin, never from the command\n"+
			"line: argv is world-readable and lands in shell history.\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		fs.Usage()
		os.Exit(2)
	}

	adminPassword, err := readAdminPassword(os.Stdin)
	if err != nil {
		log.Fatalf("Reading password: %v", err)
	}
	if len(adminPassword) < 12 {
		log.Fatal("Error: the password must be at least 12 characters")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("DB error: %v", err)
	}
	defer st.Close()

	hash, err := password.Hash(adminPassword)
	if err != nil {
		log.Fatalf("Password hashing error: %v", err)
	}

	existing, err := st.Users().GetLocalUserByUsername(ctx, *username)
	if err == nil && existing != nil {
		if err := st.Users().ResetAdminPassword(ctx, existing.ID, hash); err != nil {
			log.Fatalf("Failed to update admin: %v", err)
		}
		log.Printf("✓ Admin user %q password successfully reset", *username)
		return
	}
	// Checked only on creation, so an existing account keeps its reset path.
	if !config.ValidUsername(*username) {
		log.Fatal("Error: -username must be 3-64 characters of letters, digits, '.', '_' or '-'")
	}

	user := &store.User{
		ID:                 fmt.Sprintf("usr_%s", crypto.RandomHex(12)),
		Username:           *username,
		DisplayName:        "Administrator",
		PasswordHash:       hash,
		Role:               "admin",
		Status:             "active",
		SSOProvider:        "local",
		MustChangePassword: true,
	}

	if err := st.Users().CreateUser(ctx, user); err != nil {
		log.Fatalf("Failed to create admin: %v", err)
	}
	log.Printf("✓ Admin user %q created successfully", *username)
}

// collectFiles is what every CLI seal uses; the sealed-only members are safe here and nowhere else.
func collectFiles(ctx context.Context, cfg *config.Config) recoveryclient.Payload {
	payload, err := backup.Collect(ctx, cfg, appVersion)
	if err != nil {
		log.Fatalf("Failed to collect backup files: %v", err)
	}
	return payload
}

// mustLock takes backup.lock for a CLI seal, or exits while another run, export or drill holds it.
func mustLock(cfg *config.Config) func() {
	unlock, err := backup.Lock(cfg.Database.DataDir)
	if err != nil {
		log.Fatalf("Backup: %v", err)
	}
	return unlock
}

func runBackupDrill(args []string) {
	mustParseNoArgs("backup-drill", args)
	ctx := context.Background()
	cfg, st, err := openForSeal(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	unlock := mustLock(cfg)
	err = backupDrill(ctx, cfg, os.Stdout)
	unlock()
	if err != nil {
		st.Close()
		log.Fatal(err)
	}
}

// backupDrill seals the current payload to a throwaway key, restores it and prints each check.
func backupDrill(ctx context.Context, cfg *config.Config, w io.Writer) error {
	result, err := backup.RunDrill(ctx, cfg, collectFiles(ctx, cfg), backup.Checks)
	if err != nil {
		return fmt.Errorf("drill execution error: %w", err)
	}
	fmt.Fprintf(w, "\n=== Feature 0: KyBackup Restore Drill Summary ===\n")
	fmt.Fprintf(w, "Status:   %s\n", map[bool]string{true: "PASSED (OK)", false: "FAILED"}[result.Passed])
	fmt.Fprintf(w, "Duration: %d ms\n", result.DurationMs)
	for _, check := range result.Checks {
		status := "✓"
		if !check.Passed {
			status = "✗"
		}
		fmt.Fprintf(w, "  [%s] %s: %s\n", status, check.Name, check.Message)
	}
	fmt.Fprintln(w, "==================================================")
	if !result.Passed {
		return errors.New("restore drill failed")
	}
	return nil
}

// openForSeal opens what a CLI seal needs: the server's configuration, stored installer setup
// included as runServer loads it, so a managed console's capsule carries its credentials.
func openForSeal(ctx context.Context) (*config.Config, store.Store, error) {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return nil, nil, fmt.Errorf("DB error: %w", err)
	}
	if err := loadInstallerConfiguration(ctx, cfg, st); err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("installer configuration unavailable: %w", err)
	}
	return cfg, st, nil
}

func runExportCapsule(args []string) {
	fs := flag.NewFlagSet("export-capsule", flag.ExitOnError)
	out := fs.String("out", "", "output path (default <capsule-id>.kycap in the current directory)")
	_ = fs.Parse(args)

	ctx := context.Background()
	cfg, st, err := openForSeal(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	key, err := recoveryclient.LoadRecoveryKey(cfg.Database.DataDir, backup.Settings(ctx, st.Settings()))
	if err != nil {
		log.Fatalf("Recovery key: %v", err)
	}
	if _, err := os.Lstat(*out); *out != "" && err == nil {
		log.Fatalf("Write: %s already exists; refusing to overwrite it", *out)
	}
	unlock := mustLock(cfg)
	defer unlock()
	raw, m, err := recoveryclient.Seal(collectFiles(ctx, cfg), key)
	if err != nil {
		log.Fatalf("Seal: %v", err)
	}
	path := *out
	if path == "" {
		path = recoveryclient.FilenameSafe(m.CapsuleID) + ".kycap"
	}
	if err := writeNew(path, raw); err != nil {
		log.Fatalf("Write: %v", err)
	}
	log.Printf("✓ Capsule %s sealed to recovery key %s, written to %s (%d bytes)", m.CapsuleID, m.RecoveryKeyID, path, len(raw))
}

// writeNew puts data at path, which must not exist, through a synced 0600 temporary file in the
// same directory: a crash leaves no partial file under the name. The hard link refuses an
// existing path atomically, which a rename would replace.
func writeNew(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".kycap-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// readAdminPassword reads one line from in. A terminal gets a prompt and no echo.
func readAdminPassword(in *os.File) (string, error) {
	if fd := int(in.Fd()); term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "New admin password: ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	return readPasswordLine(in)
}

// readPasswordLine is the first line of r without its line ending.
func readPasswordLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// stdinIsTerminal reports whether a human is typing, so a pipeline gets no stray prompt.
func stdinIsTerminal() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func runRestore(args []string) {
	restoreCommand(args, restore)
}

// restoreCommand parses a restore command's flags and reads custodian shares from stdin.
func restoreCommand(args []string, run func(capsulePath, targetDir, expectService string, shares []string, stdout io.Writer) error) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	capsulePath := fs.String("capsule", "", "path to the .kycap file")
	target := fs.String("to", "", "empty directory to restore into")
	service := fs.String("service", "", "expected service name (default: $KY_APP_NAME)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: kymessages restore -capsule <file.kycap> -to <dir> [-service <name>]\n\n"+
			"Custodian shares are read from stdin, one ky2-... share per line, and never from\n"+
			"the command line: argv is world-readable and lands in shell history.\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if *capsulePath == "" || *target == "" {
		fs.Usage()
		os.Exit(2)
	}
	if *service == "" {
		// Not config.LoadFromEnv: it mints <DataDir>/encryption.key as a side effect, and a
		// recovery host has no business growing a key of its own mid-ceremony.
		*service = os.Getenv("KY_APP_NAME")
	}
	if *service == "" {
		*service = config.DefaultAppName
	}
	if *service == "" {
		log.Fatal("Error: -service is required when KY_APP_NAME is not set")
	}

	if stdinIsTerminal() {
		fmt.Fprintln(os.Stderr, "Paste custodian shares, one per line, then Ctrl-D:")
	}
	shares, err := recoveryclient.ReadShares(os.Stdin)
	if err != nil {
		log.Fatalf("Reading shares: %v", err)
	}
	if len(shares) == 0 {
		log.Fatal("Error: no custodian shares on stdin")
	}
	if err := run(*capsulePath, *target, *service, shares, os.Stdout); err != nil {
		log.Fatalf("restore failed: %v", err)
	}
}

func runRestoreAttachments(args []string) {
	fs := flag.NewFlagSet("restore-attachments", flag.ExitOnError)
	mirrorDir := fs.String("mirror", "", "path to the encrypted attachment mirror directory (<KY_BACKUP_DIR>/attachments)")
	dataDir := fs.String("data-dir", "", "path to the restored data directory containing attachments.key")
	targetDir := fs.String("to", "", "target attachments directory (KY_ATTACHMENTS_DIR)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: kymessages restore-attachments -mirror <dir> -data-dir <restored-data-dir> -to <attachments-dir>\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if *mirrorDir == "" || *dataDir == "" || *targetDir == "" {
		fs.Usage()
		os.Exit(2)
	}
	key, err := backup.LoadAttachmentKey(*dataDir)
	if err != nil {
		log.Fatalf("restore-attachments: load key: %v", err)
	}
	referencedKeys, err := backup.LoadReferencedAttachmentKeys(*dataDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("restore-attachments: read referenced attachments from %s: %v", filepath.Join(*dataDir, "ky_server.db"), err)
	}
	var count int
	if errors.Is(err, os.ErrNotExist) {
		log.Printf("restore-attachments: %s not found; restoring active mirror blobs only (skipping .pruned)", filepath.Join(*dataDir, "ky_server.db"))
		count, err = backup.RestoreAttachments(*mirrorDir, *targetDir, key)
	} else {
		count, err = backup.RestoreAttachmentsForKeys(*mirrorDir, *targetDir, key, referencedKeys)
	}
	if err != nil {
		log.Fatalf("restore-attachments failed: %v", err)
	}
	log.Printf("✓ Restored %d attachment blob(s) to %s", count, *targetDir)
}
