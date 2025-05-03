package store

import "sync"

type SessionBlacklist struct {
	mutex sync.RWMutex
	data  map[string]struct{}
}

func NewSessionBlacklist() *SessionBlacklist {
	return &SessionBlacklist{
		data: make(map[string]struct{}),
	}
}

func (bl *SessionBlacklist) In(sessionID string) bool {
	bl.mutex.RLock()
	defer bl.mutex.RUnlock()
	_, ok := bl.data[sessionID]
	return ok
}

func (bl *SessionBlacklist) Add(sessionID string) {
	bl.mutex.Lock()
	defer bl.mutex.Unlock()
	bl.data[sessionID] = struct{}{}
}
