package webhook

import (
	"time"
)

// Cron type for cache status updates, after a sync interval,
// compare last update time stored in the cache and current time, update the cache status
type Cron struct {
	syncInterval time.Duration
	log          Logger
	cache        *Cache
}

// NewCron - creates new cron object
func NewCron(syncInterval time.Duration, cache *Cache, log Logger) *Cron {
	return &Cron{
		syncInterval: syncInterval,
		log:          log,
		cache:        cache,
	}
}

// CronSync - for every sync interval, update the cache status to ensure it is up to date
func (c *Cron) CronSync(stopCh <-chan struct{}) {
	for {
		c.log.Println("Full Resync Cron Sleeping for ", c.syncInterval)
		select {
		case <-stopCh:
			c.log.Println("Resync Cron is stopped.")
			return
		case <-time.After(c.syncInterval):
			c.log.Println("CronSync starts to update cache status")
			c.cache.updateCacheStatus("")
			return
		}
	}
}
