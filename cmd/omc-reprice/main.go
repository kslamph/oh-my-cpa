// Command omc-reprice re-prices already-recorded requests of the named models at the price book's
// current price, and prices the ones that never found a price. OMC locks a request's cost when it
// is recorded; this is the operator-requested exception for correcting a wrong price. It prints
// the event and fact totals before and after so the correction can be reconciled.
//
// It takes the database lock, so OMC must be stopped.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oh-my-cpa/oh-my-cpa/internal/backup"
	"github.com/oh-my-cpa/oh-my-cpa/internal/config"
	appcrypto "github.com/oh-my-cpa/oh-my-cpa/internal/crypto"
	"github.com/oh-my-cpa/oh-my-cpa/internal/repository"
	_ "modernc.org/sqlite"
)

func run(ctx context.Context) error {
	models := flag.String("models", "", "comma-separated model names to re-price")
	dryRun := flag.Bool("dry-run", false, "report totals only")
	flag.Parse()
	var names []string
	for _, name := range strings.Split(*models, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("-models is required")
	}
	if _, err := config.LoadDotEnv(config.DotEnvPath()); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	lock, err := backup.LockDatabase(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("%w (stop omcpa first)", err)
	}
	defer lock.Close()
	wrapping, err := appcrypto.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	cipher, err := backup.ResolveCipher(cfg.DatabasePath, wrapping)
	if err != nil {
		return err
	}
	db, err := repository.Open(ctx, cfg.DatabasePath, repository.WithCipher(cipher))
	if err != nil {
		return err
	}
	defer db.Close()
	repo := repository.New(db)

	report := func(stage string) error {
		for _, model := range names {
			var events, priced, cost, fine, daily, local int64
			if err := repo.SQL().QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(pricing_status='priced'),0), COALESCE(SUM(cost_nanos),0) FROM usage_events WHERE model = ?`, model).Scan(&events, &priced, &cost); err != nil {
				return err
			}
			if err := repo.SQL().QueryRowContext(ctx, `SELECT COALESCE(SUM(cost_nanos),0) FROM usage_facts_15m WHERE model = ?`, model).Scan(&fine); err != nil {
				return err
			}
			if err := repo.SQL().QueryRowContext(ctx, `SELECT COALESCE(SUM(cost_nanos),0) FROM usage_facts_daily WHERE model = ?`, model).Scan(&daily); err != nil {
				return err
			}
			if err := repo.SQL().QueryRowContext(ctx, `SELECT COALESCE(SUM(cost_nanos),0) FROM usage_facts_local_daily WHERE model = ?`, model).Scan(&local); err != nil {
				return err
			}
			fmt.Printf("%-7s %-34s events=%d priced=%d events_usd=%.6f facts15m=%.6f factsDaily=%.6f factsLocal=%.6f\n",
				stage, model, events, priced, float64(cost)/1e9, float64(fine)/1e9, float64(daily)/1e9, float64(local)/1e9)
		}
		return nil
	}
	if err := report("before"); err != nil || *dryRun {
		return err
	}
	now := time.Now().UnixMilli()
	changed, delta, err := repo.RepriceUsage(ctx, names, now)
	if err != nil {
		return fmt.Errorf("reprice: %w", err)
	}
	var newlyPriced int64
	for _, model := range names {
		n, err := repo.PriceUnpricedUsage(ctx, model, now)
		if err != nil {
			return fmt.Errorf("price unpriced %s: %w", model, err)
		}
		newlyPriced += n
	}
	fmt.Printf("repriced=%d cost_delta_usd=%.6f newly_priced=%d\n", changed, float64(delta)/1e9, newlyPriced)
	return report("after")
}

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "omc-reprice:", err)
		os.Exit(1)
	}
}
