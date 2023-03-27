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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/minio/minio/internal/event"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/certs"
	xnet "github.com/minio/pkg/net"
)

// Webhook constants
const (
	WebhookEndpoint   = "endpoint"
	WebhookAuthToken  = "auth_token"
	WebhookQueueDir   = "queue_dir"
	WebhookQueueLimit = "queue_limit"
	WebhookClientCert = "client_cert"
	WebhookClientKey  = "client_key"

	EnvWebhookEnable     = "MINIO_NOTIFY_WEBHOOK_ENABLE"
	EnvWebhookEndpoint   = "MINIO_NOTIFY_WEBHOOK_ENDPOINT"
	EnvWebhookAuthToken  = "MINIO_NOTIFY_WEBHOOK_AUTH_TOKEN"
	EnvWebhookQueueDir   = "MINIO_NOTIFY_WEBHOOK_QUEUE_DIR"
	EnvWebhookQueueLimit = "MINIO_NOTIFY_WEBHOOK_QUEUE_LIMIT"
	EnvWebhookClientCert = "MINIO_NOTIFY_WEBHOOK_CLIENT_CERT"
	EnvWebhookClientKey  = "MINIO_NOTIFY_WEBHOOK_CLIENT_KEY"
)

// WebhookArgs - Webhook target arguments.
type WebhookArgs struct {
	Enable     bool            `json:"enable"`
	Endpoint   xnet.URL        `json:"endpoint"`
	AuthToken  string          `json:"authToken"`
	Transport  *http.Transport `json:"-"`
	QueueDir   string          `json:"queueDir"`
	QueueLimit uint64          `json:"queueLimit"`
	ClientCert string          `json:"clientCert"`
	ClientKey  string          `json:"clientKey"`
}

// Validate WebhookArgs fields
func (w WebhookArgs) Validate() error {
	if !w.Enable {
		return nil
	}
	if w.Endpoint.IsEmpty() {
		return errors.New("endpoint empty")
	}
	if w.QueueDir != "" {
		if !filepath.IsAbs(w.QueueDir) {
			return errors.New("queueDir path should be absolute")
		}
	}
	if w.ClientCert != "" && w.ClientKey == "" || w.ClientCert == "" && w.ClientKey != "" {
		return errors.New("cert and key must be specified as a pair")
	}
	return nil
}

// WebhookTarget - Webhook target.
type WebhookTarget struct {
	lazyInit lazyInit

	id         event.TargetID
	args       WebhookArgs
	transport  *http.Transport
	httpClient *http.Client
	store      Store
	loggerOnce logger.LogOnce
	cancel     context.CancelFunc
	cancelCh   <-chan struct{}
}

// ID - returns target ID.
func (target *WebhookTarget) ID() event.TargetID {
	return target.id
}

// IsActive - Return true if target is up and active
func (target *WebhookTarget) IsActive() (bool, error) {
	if err := target.init(); err != nil {
		return false, err
	}
	return target.isActive()
}

// Store returns any underlying store if set.
func (target *WebhookTarget) Store() event.TargetStore {
	return target.store
}

func (target *WebhookTarget) isActive() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target.args.Endpoint.String(), nil)
	if err != nil {
		if xnet.IsNetworkOrHostDown(err, false) {
			return false, errNotConnected
		}
		return false, err
	}
	tokens := strings.Fields(target.args.AuthToken)
	switch len(tokens) {
	case 2:
		req.Header.Set("Authorization", target.args.AuthToken)
	case 1:
		req.Header.Set("Authorization", "Bearer "+target.args.AuthToken)
	}

	resp, err := target.httpClient.Do(req)
	if err != nil {
		if xnet.IsNetworkOrHostDown(err, true) {
			return false, errNotConnected
		}
		return false, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// No network failure i.e response from the target means its up
	return true, nil
}

// Save - saves the events to the store if queuestore is configured,
// which will be replayed when the webhook connection is active.
func (target *WebhookTarget) Save(eventData event.Event) error {
	if err := target.init(); err != nil {
		return err
	}

	if target.store != nil {
		return target.store.Put(eventData)
	}
	err := target.send(eventData)
	if err != nil {
		if xnet.IsNetworkOrHostDown(err, false) {
			return errNotConnected
		}
	}
	return err
}

// send - sends an event to the webhook.
func (target *WebhookTarget) send(eventData event.Event) error {
	objectName, err := url.QueryUnescape(eventData.S3.Object.Key)
	if err != nil {
		return err
	}
	key := eventData.S3.Bucket.Name + "/" + objectName

	data, err := json.Marshal(event.Log{EventName: eventData.EventName, Key: key, Records: []event.Event{eventData}})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, target.args.Endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}

	// Verify if the authToken already contains
	// <Key> <Token> like format, if this is
	// already present we can blindly use the
	// authToken as is instead of adding 'Bearer'
	tokens := strings.Fields(target.args.AuthToken)
	switch len(tokens) {
	case 2:
		req.Header.Set("Authorization", target.args.AuthToken)
	case 1:
		req.Header.Set("Authorization", "Bearer "+target.args.AuthToken)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := target.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("sending event failed with %v", resp.Status)
	}

	return nil
}

// Send - reads an event from store and sends it to webhook.
func (target *WebhookTarget) Send(eventKey string) error {
	if err := target.init(); err != nil {
		return err
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
		if xnet.IsNetworkOrHostDown(err, false) {
			return errNotConnected
		}
		return err
	}

	// Delete the event from store.
	return target.store.Del(eventKey)
}

// Close - does nothing and available for interface compatibility.
func (target *WebhookTarget) Close() error {
	target.cancel()
	return nil
}

func (target *WebhookTarget) init() error {
	return target.lazyInit.Do(target.initWebhook)
}

// Only called from init()
func (target *WebhookTarget) initWebhook() error {
	args := target.args
	transport := target.transport

	if args.ClientCert != "" && args.ClientKey != "" {
		manager, err := certs.NewManager(context.Background(), args.ClientCert, args.ClientKey, tls.LoadX509KeyPair)
		if err != nil {
			return err
		}
		manager.ReloadOnSignal(syscall.SIGHUP) // allow reloads upon SIGHUP
		transport.TLSClientConfig.GetClientCertificate = manager.GetClientCertificate
	}
	target.httpClient = &http.Client{Transport: transport}

	yes, err := target.isActive()
	if err != nil {
		return err
	}
	if !yes {
		return errNotConnected
	}

	return nil
}

// NewWebhookTarget - creates new Webhook target.
func NewWebhookTarget(ctx context.Context, id string, args WebhookArgs, loggerOnce logger.LogOnce, transport *http.Transport) (*WebhookTarget, error) {
	ctx, cancel := context.WithCancel(ctx)

	var store Store
	if args.QueueDir != "" {
		queueDir := filepath.Join(args.QueueDir, storePrefix+"-webhook-"+id)
		store = NewQueueStore(queueDir, args.QueueLimit)
		if err := store.Open(); err != nil {
			cancel()
			return nil, fmt.Errorf("unable to initialize the queue store of Webhook `%s`: %w", id, err)
		}
	}

	target := &WebhookTarget{
		id:         event.TargetID{ID: id, Name: "webhook"},
		args:       args,
		loggerOnce: loggerOnce,
		transport:  transport,
		store:      store,
		cancel:     cancel,
		cancelCh:   ctx.Done(),
	}

	if target.store != nil {
		streamEventsFromStore(target.store, target, target.cancelCh, target.loggerOnce)
	}

	return target, nil
}
