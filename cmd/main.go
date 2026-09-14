package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/arindraaribudi/cert-manager-ext-issuer-secret-manager/internal/app"
)

func Main() int {
	var opts app.Options
	flag.StringVar(&opts.MetricsAddr, "metrics-bind-address", ":8080", "")
	flag.StringVar(&opts.HealthProbeAddr, "health-probe-bind-address", ":8081", "")
	flag.BoolVar(&opts.LeaderElect, "leader-elect", false, "")
	flag.DurationVar(&opts.ResyncInterval, "resync-interval", 24*time.Hour, "")
	flag.StringVar(&opts.CertManagerNamespace, "cert-manager-namespace", "cert-manager", "")
	flag.Parse()

	if err := app.Run(context.Background(), opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func main() { os.Exit(Main()) }
