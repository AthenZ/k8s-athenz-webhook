package webhook

import (
	"time"

	"k8s.io/client-go/kubernetes"
)

// Cron type for cron updates
type Cron struct {
	k8sClient    kubernetes.Interface
	syncInterval time.Duration
	log          Logger
	cache        *Cache
}

// NewCron - creates new cron object
func NewCron(k8sClient kubernetes.Interface, syncInterval time.Duration, cache *Cache, log Logger) *Cron {
	return &Cron{
		k8sClient:    k8sClient,
		syncInterval: syncInterval,
		log:          log,
		cache:        cache,
	}
}

// FullResync - add all namespaces to the queue for full resync
func (c *Cron) HourlySync(stopCh <-chan struct{}) {
	for {
		c.log.Println("Full Resync Cron Sleeping for ", c.syncInterval)
		select {
		case <-stopCh:
			c.log.Println("Resync Cron is stopped.")
			return
		case <-time.After(c.syncInterval):
			c.log.Println("Hourly Cron start to update cache status")
			c.cache.updateCacheStatus()
			return
		}
	}
}
