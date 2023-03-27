// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package target

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/minio/minio/internal/event"
	"github.com/minio/minio/internal/logger"
	xnet "github.com/minio/pkg/net"
)

// Redis constants
const (
	RedisFormat     = "format"
	RedisAddress    = "address"
	RedisPassword   = "password"
	RedisKey        = "key"
	RedisQueueDir   = "queue_dir"
	RedisQueueLimit = "queue_limit"

	EnvRedisEnable     = "MINIO_NOTIFY_REDIS_ENABLE"
	EnvRedisFormat     = "MINIO_NOTIFY_REDIS_FORMAT"
	EnvRedisAddress    = "MINIO_NOTIFY_REDIS_ADDRESS"
	EnvRedisPassword   = "MINIO_NOTIFY_REDIS_PASSWORD"
	EnvRedisKey        = "MINIO_NOTIFY_REDIS_KEY"
	EnvRedisQueueDir   = "MINIO_NOTIFY_REDIS_QUEUE_DIR"
	EnvRedisQueueLimit = "MINIO_NOTIFY_REDIS_QUEUE_LIMIT"
)

// RedisArgs - Redis target arguments.
type RedisArgs struct {
	Enable     bool      `json:"enable"`
	Format     string    `json:"format"`
	Addr       xnet.Host `json:"address"`
	Password   string    `json:"password"`
	Key        string    `json:"key"`
	QueueDir   string    `json:"queueDir"`
	QueueLimit uint64    `json:"queueLimit"`
}

// RedisAccessEvent holds event log data and timestamp
type RedisAccessEvent struct {
	Event     []event.Event
	EventTime string
}

// Validate RedisArgs fields
func (r RedisArgs) Validate() error {
	if !r.Enable {
		return nil
	}

	if r.Format != "" {
		f := strings.ToLower(r.Format)
		if f != event.NamespaceFormat && f != event.AccessFormat {
			return fmt.Errorf("unrecognized format")
		}
	}

	if r.Key == "" {
		return fmt.Errorf("empty key")
	}

	if r.QueueDir != "" {
		if !filepath.IsAbs(r.QueueDir) {
			return errors.New("queueDir path should be absolute")
		}
	}

	return nil
}

func (r RedisArgs) validateFormat(c redis.Conn) error {
	typeAvailable, err := redis.String(c.Do("TYPE", r.Key))
	if err != nil {
		return err
	}

	if typeAvailable != "none" {
		expectedType := "hash"
		if r.Format == event.AccessFormat {
			expectedType = "list"
		}

		if typeAvailable != expectedType {
			return fmt.Errorf("expected type %v does not match with available type %v", expectedType, typeAvailable)
		}
	}

	return nil
}

// RedisTarget - Redis target.
type RedisTarget struct {
	lazyInit lazyInit

	id         event.TargetID
	args       RedisArgs
	pool       *redis.Pool
	store      Store
	firstPing  bool
	loggerOnce logger.LogOnce
	quitCh     chan struct{}
}

// ID - returns target ID.
func (target *RedisTarget) ID() event.TargetID {
	return target.id
}

// Store returns any underlying store if set.
func (target *RedisTarget) Store() event.TargetStore {
	return target.store
}

// IsActive - Return true if target is up and active
func (target *RedisTarget) IsActive() (bool, error) {
	if err := target.init(); err != nil {
		return false, err
	}
	return target.isActive()
}

func (target *RedisTarget) isActive() (bool, error) {
	conn := target.pool.Get()
	defer conn.Close()

	_, pingErr := conn.Do("PING")
	if pingErr != nil {
		if IsConnRefusedErr(pingErr) {
			return false, errNotConnected
		}
		return false, pingErr
	}
	return true, nil
}

// Save - saves the events to the store if questore is configured, which will be replayed when the redis connection is active.
func (target *RedisTarget) Save(eventData event.Event) error {
	if err := target.init(); err != nil {
		return err
	}

	if target.store != nil {
		return target.store.Put(eventData)
	}
	_, err := target.isActive()
	if err != nil {
		return err
	}
	return target.send(eventData)
}

// send - sends an event to the redis.
func (target *RedisTarget) send(eventData event.Event) error {
	conn := target.pool.Get()
	defer conn.Close()

	if target.args.Format == event.NamespaceFormat {
		objectName, err := url.QueryUnescape(eventData.S3.Object.Key)
		if err != nil {
			return err
		}
		key := eventData.S3.Bucket.Name + "/" + objectName

		if eventData.EventName == event.ObjectRemovedDelete {
			_, err = conn.Do("HDEL", target.args.Key, key)
		} else {
			var data []byte
			if data, err = json.Marshal(struct{ Records []event.Event }{[]event.Event{eventData}}); err != nil {
				return err
			}

			_, err = conn.Do("HSET", target.args.Key, key, data)
		}
		if err != nil {
			return err
		}
	}

	if target.args.Format == event.AccessFormat {
		data, err := json.Marshal([]RedisAccessEvent{{Event: []event.Event{eventData}, EventTime: eventData.EventTime}})
		if err != nil {
			return err
		}
		if _, err := conn.Do("RPUSH", target.args.Key, data); err != nil {
			return err
		}
	}

	return nil
}

// Send - reads an event from store and sends it to redis.
func (target *RedisTarget) Send(eventKey string) error {
	if err := target.init(); err != nil {
		return err
	}

	conn := target.pool.Get()
	defer conn.Close()

	_, pingErr := conn.Do("PING")
	if pingErr != nil {
		if IsConnRefusedErr(pingErr) {
			return errNotConnected
		}
		return pingErr
	}

	if !target.firstPing {
		if err := target.args.validateFormat(conn); err != nil {
			if IsConnRefusedErr(err) {
				return errNotConnected
			}
			return err
		}
		target.firstPing = true
	}

	eventData, eErr := target.store.Get(eventKey)
	if eErr != nil {
		// The last event key in a successful batch will be sent in the channel atmost once by the replayEvents()
		// Such events will not exist and would've been already been sent successfully.
		if os.IsNotExist(eErr) {
			return nil
		}
		return eErr
	}

	if err := target.send(eventData); err != nil {
		if IsConnRefusedErr(err) {
			return errNotConnected
		}
		return err
	}

	// Delete the event from store.
	return target.store.Del(eventKey)
}

// Close - releases the resources used by the pool.
func (target *RedisTarget) Close() error {
	close(target.quitCh)
	return target.pool.Close()
}

func (target *RedisTarget) init() error {
	return target.lazyInit.Do(target.initRedis)
}

func (target *RedisTarget) initRedis() error {
	conn := target.pool.Get()
	defer conn.Close()

	_, pingErr := conn.Do("PING")
	if pingErr != nil {
		if !(IsConnRefusedErr(pingErr) || IsConnResetErr(pingErr)) {
			target.loggerOnce(context.Background(), pingErr, target.ID().String())
		}
		return pingErr
	}

	if err := target.args.validateFormat(conn); err != nil {
		target.loggerOnce(context.Background(), err, target.ID().String())
		return err
	}

	target.firstPing = true

	yes, err := target.isActive()
	if err != nil {
		return err
	}
	if !yes {
		return errNotConnected
	}

	return nil
}

// NewRedisTarget - creates new Redis target.
func NewRedisTarget(id string, args RedisArgs, loggerOnce logger.LogOnce) (*RedisTarget, error) {
	var store Store
	if args.QueueDir != "" {
		queueDir := filepath.Join(args.QueueDir, storePrefix+"-redis-"+id)
		store = NewQueueStore(queueDir, args.QueueLimit)
		if err := store.Open(); err != nil {
			return nil, fmt.Errorf("unable to initialize the queue store of Redis `%s`: %w", id, err)
		}
	}

	pool := &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 2 * 60 * time.Second,
		Dial: func() (redis.Conn, error) {
			conn, err := redis.Dial("tcp", args.Addr.String())
			if err != nil {
				return nil, err
			}

			if args.Password != "" {
				if _, err = conn.Do("AUTH", args.Password); err != nil {
					conn.Close()
					return nil, err
				}
			}

			// Must be done after AUTH
			if _, err = conn.Do("CLIENT", "SETNAME", "MinIO"); err != nil {
				conn.Close()
				return nil, err
			}

			return conn, nil
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
	}

	target := &RedisTarget{
		id:         event.TargetID{ID: id, Name: "redis"},
		args:       args,
		pool:       pool,
		store:      store,
		loggerOnce: loggerOnce,
		quitCh:     make(chan struct{}),
	}

	if target.store != nil {
		streamEventsFromStore(target.store, target, target.quitCh, target.loggerOnce)
	}

	return target, nil
}
