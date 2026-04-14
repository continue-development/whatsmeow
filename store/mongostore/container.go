// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mongostore

import (
	"context"
	"errors"
	"fmt"
	mathRand "math/rand/v2"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"


	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
	"go.mau.fi/util/random"
)

type Container struct {
	client *mongo.Client
	db     *mongo.Database
	log    waLog.Logger

	deviceColl *mongo.Collection
	LIDMap     *CachedLIDMap
}

var _ store.DeviceContainer = (*Container)(nil)

func New(ctx context.Context, uri, dbName string, log waLog.Logger) (*Container, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}
	return NewWithClient(ctx, client, dbName, log)
}

func NewWithClient(ctx context.Context, client *mongo.Client, dbName string, log waLog.Logger) (*Container, error) {
	if log == nil {
		log = waLog.Noop
	}
	db := client.Database(dbName)
	container := &Container{
		client:     client,
		db:         db,
		log:        log,
		deviceColl: db.Collection("whatsmeow_device"),
		LIDMap:     NewCachedLIDMap(db),
	}

	// Create indices
	container.createIndices(ctx)

	return container, nil
}

func (c *Container) createIndices(ctx context.Context) {
	idx := func(coll *mongo.Collection, keys bson.M, unique bool) {
		opts := options.Index()
		if unique {
			opts.SetUnique(true)
		}
		_, _ = coll.Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys:    keys,
			Options: opts,
		})
	}

	idx(c.deviceColl, bson.M{"jid": 1}, true)
	idx(c.LIDMap.coll, bson.M{"lid": 1}, true)
	idx(c.LIDMap.coll, bson.M{"pn": 1}, true)

	db := c.db
	idx(db.Collection("whatsmeow_identity_keys"), bson.M{"our_jid": 1, "their_id": 1}, true)
	idx(db.Collection("whatsmeow_sessions"), bson.M{"our_jid": 1, "their_id": 1}, true)
	idx(db.Collection("whatsmeow_pre_keys"), bson.M{"jid": 1, "key_id": 1}, true)
	idx(db.Collection("whatsmeow_sender_keys"), bson.M{"our_jid": 1, "chat_id": 1, "sender_id": 1}, true)
	idx(db.Collection("whatsmeow_app_state_sync_keys"), bson.M{"jid": 1, "key_id": 1}, true)
	idx(db.Collection("whatsmeow_app_state_version"), bson.M{"jid": 1, "name": 1}, true)
	idx(db.Collection("whatsmeow_app_state_mutation_macs"), bson.M{"jid": 1, "name": 1, "index_mac": 1}, false)
	idx(db.Collection("whatsmeow_contacts"), bson.M{"our_jid": 1, "their_jid": 1}, true)
	idx(db.Collection("whatsmeow_chat_settings"), bson.M{"our_jid": 1, "chat_id": 1}, true)
	idx(db.Collection("whatsmeow_message_secrets"), bson.M{"our_jid": 1, "chat_id": 1, "sender_id": 1, "message_id": 1}, true)
	idx(db.Collection("whatsmeow_privacy_tokens"), bson.M{"our_jid": 1, "their_jid": 1}, true)
	idx(db.Collection("whatsmeow_buffered_events"), bson.M{"ciphertext_hash": 1}, true)
	idx(db.Collection("whatsmeow_outgoing_events"), bson.M{"chat_jid": 1, "message_id": 1}, true)
}




func (c *Container) NewDevice() *store.Device {
	device := &store.Device{
		Log:       c.log,
		Container: c,

		NoiseKey:       keys.NewKeyPair(),
		IdentityKey:    keys.NewKeyPair(),
		RegistrationID: mathRand.Uint32(),
		AdvSecretKey:   random.Bytes(32),
	}
	device.SignedPreKey = device.IdentityKey.CreateSignedPreKey(1)
	return device
}

func (c *Container) PutDevice(ctx context.Context, device *store.Device) error {
	if device.ID == nil {
		return errors.New("device JID must be known before accessing database")
	}

	noisePriv := device.NoiseKey.Priv[:]
	identityPriv := device.IdentityKey.Priv[:]
	signedPreKeyPriv := device.SignedPreKey.Priv[:]
	signedPreKeySig := device.SignedPreKey.Signature[:]

	update := bson.M{
		"$set": bson.M{
			"lid":              device.LID.String(),
			"platform":         device.Platform,
			"business_name":    device.BusinessName,
			"push_name":        device.PushName,
			"lid_migration_ts": device.LIDMigrationTimestamp,
			"identifier":       device.Identifier,
		},
		"$setOnInsert": bson.M{
			"registration_id":     device.RegistrationID,
			"noise_key":           noisePriv,
			"identity_key":        identityPriv,
			"signed_pre_key":      signedPreKeyPriv,
			"signed_pre_key_id":   device.SignedPreKey.KeyID,
			"signed_pre_key_sig":  signedPreKeySig,
			"adv_key":             device.AdvSecretKey,
			"adv_details":         device.Account.Details,
			"adv_account_sig":     device.Account.AccountSignature,
			"adv_account_sig_key": device.Account.AccountSignatureKey,
			"adv_device_sig":      device.Account.DeviceSignature,
			"facebook_uuid":       device.FacebookUUID.String(),
			"server_id":           device.ServerID,
		},
	}

	_, err := c.deviceColl.UpdateOne(ctx, bson.M{"jid": device.ID.String()}, update, options.UpdateOne().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("failed to save device: %w", err)
	}

	if !device.Initialized {
		c.initializeDevice(device)
	}
	return nil
}

func (c *Container) initializeDevice(device *store.Device) {
	innerStore := NewMongoStore(c, device.ID.String())
	device.Identities = innerStore
	device.Sessions = innerStore
	device.PreKeys = innerStore
	device.SenderKeys = innerStore
	device.AppStateKeys = innerStore
	device.AppState = innerStore
	device.Contacts = innerStore
	device.ChatSettings = innerStore
	device.MsgSecrets = innerStore
	device.PrivacyTokens = innerStore
	device.EventBuffer = innerStore
	device.LIDs = c.LIDMap
	device.Container = c
	device.Initialized = true
}


func (c *Container) GetDevice(ctx context.Context, jid types.JID) (*store.Device, error) {
	var res bson.M
	err := c.deviceColl.FindOne(ctx, bson.M{"jid": jid.String()}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}
	return c.decodeDevice(res)
}

func (c *Container) decodeDevice(res bson.M) (*store.Device, error) {
	var device store.Device
	device.Log = c.log
	device.SignedPreKey = &keys.PreKey{}
	
	jidStr, _ := res["jid"].(string)
	jid, err := types.ParseJID(jidStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JID: %w", err)
	}
	device.ID = &jid

	lidStr, _ := res["lid"].(string)
	if lidStr != "" {
		device.LID, _ = types.ParseJID(lidStr)
	}

	regID, _ := res["registration_id"].(int64)
	device.RegistrationID = uint32(regID)

	noisePriv := asByteSlice(res["noise_key"])
	identityPriv := asByteSlice(res["identity_key"])
	preKeyPriv := asByteSlice(res["signed_pre_key"])
	preKeyID, _ := res["signed_pre_key_id"].(int64)
	preKeySig := asByteSlice(res["signed_pre_key_sig"])

	if len(noisePriv) != 32 || len(identityPriv) != 32 || len(preKeyPriv) != 32 || len(preKeySig) != 64 {
		return nil, errors.New("invalid key lengths in database")
	}

	device.NoiseKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(noisePriv))
	device.IdentityKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(identityPriv))
	device.SignedPreKey.KeyPair = *keys.NewKeyPairFromPrivateKey(*(*[32]byte)(preKeyPriv))
	device.SignedPreKey.KeyID = uint32(preKeyID)
	device.SignedPreKey.Signature = (*[64]byte)(preKeySig)

	device.AdvSecretKey = asByteSlice(res["adv_key"])
	
	var account waAdv.ADVSignedDeviceIdentity
	account.Details = asByteSlice(res["adv_details"])
	account.AccountSignature = asByteSlice(res["adv_account_sig"])
	account.AccountSignatureKey = asByteSlice(res["adv_account_sig_key"])
	account.DeviceSignature = asByteSlice(res["adv_device_sig"])
	device.Account = &account

	device.Platform, _ = res["platform"].(string)
	device.BusinessName, _ = res["business_name"].(string)
	device.PushName, _ = res["push_name"].(string)
	
	fbUUIDStr, _ := res["facebook_uuid"].(string)
	if fbUUIDStr != "" {
		device.FacebookUUID, _ = uuid.Parse(fbUUIDStr)
	}
	
	lidMigTs, _ := res["lid_migration_ts"].(int64)
	device.LIDMigrationTimestamp = lidMigTs

	device.ServerID, _ = res["server_id"].(string)
	device.Identifier, _ = res["identifier"].(string)

	c.initializeDevice(&device)
	return &device, nil
}

func (c *Container) GetAllDevices(ctx context.Context, serverID string, identifier string) ([]*store.Device, error) {
	filter := bson.M{}
	if serverID != "" {
		filter["server_id"] = serverID
	}
	if identifier != "" {
		filter["identifier"] = identifier
	}

	cursor, err := c.deviceColl.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query devices: %w", err)
	}
	defer cursor.Close(ctx)

	var devices []*store.Device
	for cursor.Next(ctx) {
		var res bson.M
		if err := cursor.Decode(&res); err != nil {
			return nil, fmt.Errorf("failed to decode device: %w", err)
		}
		dev, err := c.decodeDevice(res)
		if err != nil {
			return nil, err
		}
		devices = append(devices, dev)
	}
	return devices, nil
}

func (c *Container) GetDevicesByServerID(ctx context.Context, serverID string) ([]*store.Device, error) {
	return c.GetAllDevices(ctx, serverID, "")
}

func (c *Container) GetFirstDeviceByServerID(ctx context.Context, serverID string) (*store.Device, error) {
	return c.GetDeviceByServerIDAndIdentifier(ctx, serverID, "")
}

func (c *Container) GetDeviceByServerIDAndIdentifier(ctx context.Context, serverID, identifier string) (*store.Device, error) {
	devices, err := c.GetAllDevices(ctx, serverID, identifier)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		dev := c.NewDevice()
		dev.ServerID = serverID
		dev.Identifier = identifier
		return dev, nil
	}
	return devices[0], nil
}

// GetFirstDevice is a convenience method for getting the first device in the store.
func (c *Container) GetFirstDevice(ctx context.Context) (*store.Device, error) {
	devices, err := c.GetAllDevices(ctx, "", "")
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return c.NewDevice(), nil
	} else {
		return devices[0], nil
	}
}

func (c *Container) DeleteDevice(ctx context.Context, device *store.Device) error {
	if device.ID == nil {
		return errors.New("device JID must be known before accessing database")
	}
	_, err := c.deviceColl.DeleteOne(ctx, bson.M{"jid": device.ID.String()})
	return err
}

func (c *Container) Close() error {
	return c.client.Disconnect(context.Background())
}

func asByteSlice(val interface{}) []byte {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case []byte:
		return v
	case bson.Binary:
		return v.Data
	default:
		return nil
	}
}
