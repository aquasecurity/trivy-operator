package utils

import (
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/gorhill/cronexpr"
	"k8s.io/utils/ptr"
	"time"
)

// NextCronDuration check if next cron activation time has exceeded if so return true
// if activation time has not reached return false and remaining time
// in case it failed to parse cron expression return error
func NextCronDuration(cronString string, creationTime time.Time, clock ext.Clock) (time.Duration, error) {
	expr, err := cronexpr.Parse(cronString)
	if err != nil {
		return time.Duration(0), err
	}
	return timeToExpiration(expr.Next(creationTime), clock), nil
}

// DurationExceeded  check if duration is now meaning zero
func DurationExceeded(duration time.Duration) bool {
	return duration.Nanoseconds() <= 0
}

// timeToExpiration  return the duration between time to expiration
func timeToExpiration(expiresAt time.Time, clock ext.Clock) time.Duration {
	return expiresAt.Sub(clock.Now())
}

// IsTTLExpired check whether current time has exceeded creation time + ttl duration
func IsTTLExpired(ttl time.Duration, creationTime time.Time, clock ext.Clock) (bool, time.Duration) {
	durationToTTLExpiration := timeToExpiration(creationTime.Add(ttl), clock)
	return DurationExceeded(durationToTTLExpiration), durationToTTLExpiration
}

func DurationSecondsPtr(d time.Duration) *int64 {
	if d > 0 {
		return ptr.To[int64](int64(d.Seconds()))
	}
	return nil
}
