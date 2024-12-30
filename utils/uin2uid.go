package utils

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"time"
)

var GlobalCaches *Uid2UinListCaches

func init() {
	bot := &Uid2UinListConfig{
		Configuration: struct {
			ContactListCache struct {
				SaveIntervalMillis int
			}
		}{
			ContactListCache: struct {
				SaveIntervalMillis int
			}{
				SaveIntervalMillis: 5000,
			},
		},
	}
	GlobalCaches = NewUid2UinListCaches(bot, "data/cache/uin2uid.txt")
}

type Uid2UinListCache struct {
	UID string `json:"uid"`
	UIN int64  `json:"uin"`
}

type Uid2UinListCaches struct {
	config       *Uid2UinListConfig
	records      map[int64]bool
	uidMaps      map[string]Uid2UinListCache
	uinMaps      map[int64]Uid2UinListCache
	unSaved      []Uid2UinListCache
	cacheFile    string
	uidListSaver *time.Ticker
}

func NewUid2UinListCaches(bot *Uid2UinListConfig, cacheFilePath string) *Uid2UinListCaches {
	caches := &Uid2UinListCaches{
		config:       bot,
		records:      make(map[int64]bool),
		uidMaps:      make(map[string]Uid2UinListCache),
		uinMaps:      make(map[int64]Uid2UinListCache),
		unSaved:      make([]Uid2UinListCache, 0),
		cacheFile:    cacheFilePath,
		uidListSaver: time.NewTicker(time.Duration(bot.Configuration.ContactListCache.SaveIntervalMillis) * time.Millisecond),
	}
	go caches.startSaver()
	caches.loadCaches()
	return caches
}

func (caches *Uid2UinListCaches) startSaver() {
	for range caches.uidListSaver.C {
		caches.saveUIDCaches()
	}
}

func (caches *Uid2UinListCaches) saveUIDCaches() {
	currentChanged := caches.takeCurrentUnSaved()
	if len(currentChanged) > 0 {
		file, err := os.OpenFile(caches.cacheFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		defer file.Close()

		writer := bufio.NewWriter(file)
		for _, cache := range currentChanged {
			cacheBytes, err := json.Marshal(cache)
			if err != nil {
				continue
			}
			_, err = writer.WriteString(string(cacheBytes) + "\n")
			if err != nil {
				continue
			}
		}
		writer.Flush()
	}
}

func (caches *Uid2UinListCaches) loadCaches() {
	file, err := os.OpenFile(caches.cacheFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var cache Uid2UinListCache
		err := json.Unmarshal([]byte(scanner.Text()), &cache)
		if err != nil {
			continue
		}
		caches.fastAdd(cache)
	}
}

func (caches *Uid2UinListCaches) fastAdd(data Uid2UinListCache) {
	caches.records[data.UIN] = true
	caches.uidMaps[data.UID] = data
	caches.uinMaps[data.UIN] = data
}

func (caches *Uid2UinListCaches) takeCurrentUnSaved() []Uid2UinListCache {
	var ret []Uid2UinListCache
	for _, cache := range caches.unSaved {
		ret = append(ret, cache)
	}
	caches.unSaved = nil
	return ret
}

func (caches *Uid2UinListCaches) Add(uid string, uin int64) {
	if _, exists := caches.records[uin]; exists {
		return
	}
	cache := Uid2UinListCache{UID: uid, UIN: uin}
	caches.records[uin] = true
	caches.unSaved = append(caches.unSaved, cache)
	caches.uidMaps[uid] = cache
	caches.uinMaps[uin] = cache
	caches.uidListSaver.Reset(time.Duration(caches.config.Configuration.ContactListCache.SaveIntervalMillis) * time.Millisecond)
}

func (caches *Uid2UinListCaches) GetByUID(uid string) *Uid2UinListCache {
	cache, exists := caches.uidMaps[uid]
	if !exists {
		return nil
	}
	return &cache
}

func (caches *Uid2UinListCaches) GetByUIN(uin int64) *Uid2UinListCache {
	cache, exists := caches.uinMaps[uin]
	if !exists {
		return &Uid2UinListCache{UID: strconv.FormatInt(uin, 10), UIN: uin}
	}
	return &cache
}

type Uid2UinListConfig struct {
	Configuration struct {
		ContactListCache struct {
			SaveIntervalMillis int
		}
	}
}
