package whois

import (
	"testing"
	"time"
)

func TestCappedTTL(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		deadlines []time.Time
		want      time.Duration
	}{
		{name: "no deadlines", deadlines: nil, want: cacheTTL},
		{name: "zero deadline ignored", deadlines: []time.Time{{}}, want: cacheTTL},
		{name: "deadline beyond base", deadlines: []time.Time{now.Add(60 * 24 * time.Hour)}, want: cacheTTL},
		{name: "deadline inside base", deadlines: []time.Time{now.Add(48 * time.Hour)}, want: 48 * time.Hour},
		{name: "deadline within floor window stays exact", deadlines: []time.Time{now.Add(2 * time.Minute)}, want: 2 * time.Minute},
		{name: "past deadline floors", deadlines: []time.Time{now.Add(-time.Hour)}, want: minCacheTTL},
	}
	for _, c := range cases {
		got := cappedTTL(cacheTTL, c.deadlines...)
		// cappedTTL calls time.Now() itself, so allow a small skew.
		if diff := got - c.want; diff < -time.Second || diff > time.Second {
			t.Errorf("%s: got %v, want ~%v", c.name, got, c.want)
		}
	}
}

func TestWhoisCacheHonorsPerEntryTTL(t *testing.T) {
	c := newWhoisCache(10)

	c.Set("live.example", Info{RegistrarName: "live"}, time.Hour)
	if _, ok := c.Get("live.example"); !ok {
		t.Error("entry with 1h TTL should be a hit")
	}

	c.Set("dead.example", Info{RegistrarName: "dead"}, -time.Second)
	if _, ok := c.Get("dead.example"); ok {
		t.Error("entry with already-elapsed TTL should be a miss")
	}

	// Updating an existing entry must apply the new TTL, not the original one.
	c.Set("live.example", Info{RegistrarName: "live"}, -time.Second)
	if _, ok := c.Get("live.example"); ok {
		t.Error("updated entry with elapsed TTL should be a miss")
	}
}
