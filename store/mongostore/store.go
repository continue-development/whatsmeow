// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mongostore

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

type MongoStore struct {
	*Container
	JID string

	preKeyLock sync.Mutex

	contactCache     map[types.JID]*types.ContactInfo
	contactCacheLock sync.Mutex

	idColl              *mongo.Collection
	sessionColl         *mongo.Collection
	preKeyColl          *mongo.Collection
	senderKeyColl       *mongo.Collection
	appStateSyncKeyColl *mongo.Collection
	appStateVersionColl *mongo.Collection
	appStateMutationColl *mongo.Collection
	contactColl         *mongo.Collection
	chatSettingsColl    *mongo.Collection
	msgSecretColl       *mongo.Collection
	privacyTokenColl    *mongo.Collection
	eventBufferColl     *mongo.Collection
	outgoingEventColl   *mongo.Collection
}

func NewMongoStore(c *Container, jid string) *MongoStore {
	s := &MongoStore{
		Container:    c,
		JID:          jid,
		contactCache: make(map[types.JID]*types.ContactInfo),

		idColl:              c.db.Collection("whatsmeow_identity_keys"),
		sessionColl:         c.db.Collection("whatsmeow_sessions"),
		preKeyColl:          c.db.Collection("whatsmeow_pre_keys"),
		senderKeyColl:       c.db.Collection("whatsmeow_sender_keys"),
		appStateSyncKeyColl: c.db.Collection("whatsmeow_app_state_sync_keys"),
		appStateVersionColl: c.db.Collection("whatsmeow_app_state_version"),
		appStateMutationColl: c.db.Collection("whatsmeow_app_state_mutation_macs"),
		contactColl:         c.db.Collection("whatsmeow_contacts"),
		chatSettingsColl:    c.db.Collection("whatsmeow_chat_settings"),
		msgSecretColl:       c.db.Collection("whatsmeow_message_secrets"),
		privacyTokenColl:    c.db.Collection("whatsmeow_privacy_tokens"),
		eventBufferColl:     c.db.Collection("whatsmeow_buffered_events"),
		outgoingEventColl:   c.db.Collection("whatsmeow_outgoing_events"),
	}
	return s
}

var _ store.AllSessionSpecificStores = (*MongoStore)(nil)

// IdentityStore

func (s *MongoStore) PutIdentity(ctx context.Context, address string, key [32]byte) error {
	filter := bson.M{"our_jid": s.JID, "their_id": address}
	update := bson.M{"$set": bson.M{"identity": key[:]}}
	_, err := s.idColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
	return err
}

func (s *MongoStore) DeleteAllIdentities(ctx context.Context, phone string) error {
	filter := bson.M{"our_jid": s.JID, "their_id": bson.M{"$regex": "^" + phone + ":"}}
	_, err := s.idColl.DeleteMany(ctx, filter)
	return err
}

func (s *MongoStore) DeleteIdentity(ctx context.Context, address string) error {
	filter := bson.M{"our_jid": s.JID, "their_id": address}
	_, err := s.idColl.DeleteOne(ctx, filter)
	return err
}

func (s *MongoStore) IsTrustedIdentity(ctx context.Context, address string, key [32]byte) (bool, error) {
	var res bson.M
	err := s.idColl.FindOne(ctx, bson.M{"our_jid": s.JID, "their_id": address}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return true, nil
		}
		return false, err
	}
	existingIdentity := asByteSlice(res["identity"])
	if len(existingIdentity) != 32 {
		return false, errors.New("invalid identity key length in database")
	}
	return *(*[32]byte)(existingIdentity) == key, nil
}

// SessionStore

func (s *MongoStore) GetSession(ctx context.Context, address string) ([]byte, error) {
	var res bson.M
	err := s.sessionColl.FindOne(ctx, bson.M{"our_jid": s.JID, "their_id": address}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	session := asByteSlice(res["session"])
	return session, nil
}

func (s *MongoStore) HasSession(ctx context.Context, address string) (bool, error) {
	count, err := s.sessionColl.CountDocuments(ctx, bson.M{"our_jid": s.JID, "their_id": address})
	return count > 0, err
}

func (s *MongoStore) GetManySessions(ctx context.Context, addresses []string) (map[string][]byte, error) {
	if len(addresses) == 0 {
		return nil, nil
	}
	cursor, err := s.sessionColl.Find(ctx, bson.M{"our_jid": s.JID, "their_id": bson.M{"$in": addresses}})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	result := make(map[string][]byte, len(addresses))
	for _, addr := range addresses {
		result[addr] = nil
	}
	for cursor.Next(ctx) {
		var res bson.M
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		addr, _ := res["their_id"].(string)
		session := asByteSlice(res["session"])
		result[addr] = session
	}
	return result, nil
}

func (s *MongoStore) PutSession(ctx context.Context, address string, session []byte) error {
	filter := bson.M{"our_jid": s.JID, "their_id": address}
	update := bson.M{"$set": bson.M{"session": session}}
	_, err := s.sessionColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
	return err
}

func (s *MongoStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	var models []mongo.WriteModel
	for addr, sess := range sessions {
		filter := bson.M{"our_jid": s.JID, "their_id": addr}
		update := bson.M{"$set": bson.M{"session": sess}}
		models = append(models, mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update).SetUpsert(true))
	}
	if len(models) == 0 {
		return nil
	}
	_, err := s.sessionColl.BulkWrite(ctx, models)
	return err
}

func (s *MongoStore) DeleteAllSessions(ctx context.Context, phone string) error {
	filter := bson.M{"our_jid": s.JID, "their_id": bson.M{"$regex": "^" + phone + ":"}}
	_, err := s.sessionColl.DeleteMany(ctx, filter)
	return err
}

func (s *MongoStore) DeleteSession(ctx context.Context, address string) error {
	filter := bson.M{"our_jid": s.JID, "their_id": address}
	_, err := s.sessionColl.DeleteOne(ctx, filter)
	return err
}

func (s *MongoStore) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	pnStr := pn.User
	lidStr := lid.User

	// Update sessions
	cursor, err := s.sessionColl.Find(ctx, bson.M{"our_jid": s.JID, "their_id": bson.M{"$regex": "^" + pnStr + ":"}})
	if err == nil {
		for cursor.Next(ctx) {
			var res bson.M
			if err := cursor.Decode(&res); err != nil {
				continue
			}
			addr := res["their_id"].(string)
			newAddr := lidStr + addr[len(pnStr):]
			s.PutSession(ctx, newAddr, asByteSlice(res["session"]))
		}
		cursor.Close(ctx)
	}

	// Update identity keys
	cursor, err = s.idColl.Find(ctx, bson.M{"our_jid": s.JID, "their_id": bson.M{"$regex": "^" + pnStr + ":"}})
	if err == nil {
		for cursor.Next(ctx) {
			var res bson.M
			if err := cursor.Decode(&res); err != nil {
				continue
			}
			addr := res["their_id"].(string)
			newAddr := lidStr + addr[len(pnStr):]
			s.PutIdentity(ctx, newAddr, *(*[32]byte)(asByteSlice(res["identity"])))
		}
		cursor.Close(ctx)
	}

	// Update sender keys
	_, err = s.senderKeyColl.UpdateMany(ctx,
		bson.M{"our_jid": s.JID, "sender_id": bson.M{"$regex": "^" + pnStr + ":"}},
		[]bson.M{{"$set": bson.M{"sender_id": bson.M{"$replaceOne": bson.M{"input": "$sender_id", "find": pnStr, "replacement": lidStr}}}}})

	return err
}


// PreKeyStore

func (s *MongoStore) GenOnePreKey(ctx context.Context) (*keys.PreKey, error) {
	s.preKeyLock.Lock()
	defer s.preKeyLock.Unlock()
	
	var lastKey bson.M
	err := s.preKeyColl.FindOne(ctx, bson.M{"jid": s.JID}, options.FindOne().SetSort(bson.M{"key_id": -1})).Decode(&lastKey)
	var nextID uint32 = 1
	if err == nil {
		if id, ok := lastKey["key_id"].(int64); ok {
			nextID = uint32(id) + 1
		}
	} else if !errors.Is(err, mongo.ErrNoDocuments) {
		return nil, err
	}
	
	key := keys.NewPreKey(nextID)
	_, err = s.preKeyColl.InsertOne(ctx, bson.M{
		"jid":      s.JID,
		"key_id":   key.KeyID,
		"key":      key.Priv[:],
		"uploaded": true,
	})
	return key, err
}

func (s *MongoStore) GetOrGenPreKeys(ctx context.Context, count uint32) ([]*keys.PreKey, error) {
	s.preKeyLock.Lock()
	defer s.preKeyLock.Unlock()

	cursor, err := s.preKeyColl.Find(ctx, bson.M{"jid": s.JID, "uploaded": false}, options.Find().SetLimit(int64(count)).SetSort(bson.M{"key_id": 1}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var preKeys []*keys.PreKey
	for cursor.Next(ctx) {
		var res bson.M
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		priv := asByteSlice(res["key"])
		id, _ := res["key_id"].(int64)
		if len(priv) == 32 {
			preKeys = append(preKeys, &keys.PreKey{
				KeyPair: *keys.NewKeyPairFromPrivateKey(*(*[32]byte)(priv)),
				KeyID:   uint32(id),
			})
		}
	}

	remaining := int(count) - len(preKeys)
	if remaining > 0 {
		var lastKey bson.M
		err := s.preKeyColl.FindOne(ctx, bson.M{"jid": s.JID}, options.FindOne().SetSort(bson.M{"key_id": -1})).Decode(&lastKey)
		var nextID uint32 = 1
		if err == nil {
			if id, ok := lastKey["key_id"].(int64); ok {
				nextID = uint32(id) + 1
			}
		}

		for i := 0; i < remaining; i++ {
			key := keys.NewPreKey(nextID)
			_, err = s.preKeyColl.InsertOne(ctx, bson.M{
				"jid":      s.JID,
				"key_id":   key.KeyID,
				"key":      key.Priv[:],
				"uploaded": false,
			})
			if err != nil {
				return nil, err
			}
			preKeys = append(preKeys, key)
			nextID++
		}
	}

	return preKeys, nil
}

func (s *MongoStore) GetPreKey(ctx context.Context, id uint32) (*keys.PreKey, error) {
	var res bson.M
	err := s.preKeyColl.FindOne(ctx, bson.M{"jid": s.JID, "key_id": id}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	priv := asByteSlice(res["key"])
	if len(priv) != 32 {
		return nil, errors.New("invalid prekey length in database")
	}
	return &keys.PreKey{
		KeyPair: *keys.NewKeyPairFromPrivateKey(*(*[32]byte)(priv)),
		KeyID:   id,
	}, nil
}

func (s *MongoStore) RemovePreKey(ctx context.Context, id uint32) error {
	_, err := s.preKeyColl.DeleteOne(ctx, bson.M{"jid": s.JID, "key_id": id})
	return err
}

func (s *MongoStore) MarkPreKeysAsUploaded(ctx context.Context, upToID uint32) error {
	filter := bson.M{"jid": s.JID, "key_id": bson.M{"$lte": upToID}}
	update := bson.M{"$set": bson.M{"uploaded": true}}
	_, err := s.preKeyColl.UpdateMany(ctx, filter, update)
	return err
}

func (s *MongoStore) UploadedPreKeyCount(ctx context.Context) (int, error) {
	count, err := s.preKeyColl.CountDocuments(ctx, bson.M{"jid": s.JID, "uploaded": true})
	return int(count), err
}

// SenderKeyStore

func (s *MongoStore) PutSenderKey(ctx context.Context, group, user string, session []byte) error {
	filter := bson.M{"our_jid": s.JID, "chat_id": group, "sender_id": user}
	update := bson.M{"$set": bson.M{"sender_key": session}}
	_, err := s.senderKeyColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
	return err
}

func (s *MongoStore) GetSenderKey(ctx context.Context, group, user string) ([]byte, error) {
	var res bson.M
	err := s.senderKeyColl.FindOne(ctx, bson.M{"our_jid": s.JID, "chat_id": group, "sender_id": user}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	key := asByteSlice(res["sender_key"])
	return key, nil
}

// AppStateSyncKeyStore

func (s *MongoStore) PutAppStateSyncKey(ctx context.Context, id []byte, key store.AppStateSyncKey) error {
	update := bson.M{
		"$set": bson.M{
			"key_data":    key.Data,
			"timestamp":   key.Timestamp,
			"fingerprint": key.Fingerprint,
		},
	}
	_, err := s.appStateSyncKeyColl.UpdateOne(ctx, bson.M{"jid": s.JID, "key_id": id}, update, options.UpdateOne().SetUpsert(true))
	return err
}

func (s *MongoStore) GetAppStateSyncKey(ctx context.Context, id []byte) (*store.AppStateSyncKey, error) {
	var res bson.M
	err := s.appStateSyncKeyColl.FindOne(ctx, bson.M{"jid": s.JID, "key_id": id}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	data := asByteSlice(res["key_data"])
	ts, _ := res["timestamp"].(int64)
	fp := asByteSlice(res["fingerprint"])
	return &store.AppStateSyncKey{
		Data:        data,
		Timestamp:   ts,
		Fingerprint: fp,
	}, nil
}

func (s *MongoStore) GetLatestAppStateSyncKeyID(ctx context.Context) ([]byte, error) {
	var res bson.M
	err := s.appStateSyncKeyColl.FindOne(ctx, bson.M{"jid": s.JID}, options.FindOne().SetSort(bson.M{"timestamp": -1})).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	id := asByteSlice(res["key_id"])
	return id, nil
}

func (s *MongoStore) GetAllAppStateSyncKeys(ctx context.Context) ([]*store.AppStateSyncKey, error) {
	cursor, err := s.appStateSyncKeyColl.Find(ctx, bson.M{"jid": s.JID}, options.Find().SetSort(bson.M{"timestamp": -1}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var out []*store.AppStateSyncKey
	for cursor.Next(ctx) {
		var res bson.M
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		data := asByteSlice(res["key_data"])
		ts, _ := res["timestamp"].(int64)
		fp := asByteSlice(res["fingerprint"])
		out = append(out, &store.AppStateSyncKey{
			Data:        data,
			Timestamp:   ts,
			Fingerprint: fp,
		})
	}
	return out, nil
}

// AppStateStore

func (s *MongoStore) PutAppStateVersion(ctx context.Context, name string, version uint64, hash [128]byte) error {
	filter := bson.M{"jid": s.JID, "name": name}
	update := bson.M{
		"$set": bson.M{
			"version": version,
			"hash":    hash[:],
		},
	}
	_, err := s.appStateVersionColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
	return err
}

func (s *MongoStore) GetAppStateVersion(ctx context.Context, name string) (uint64, [128]byte, error) {
	var res bson.M
	err := s.appStateVersionColl.FindOne(ctx, bson.M{"jid": s.JID, "name": name}).Decode(&res)
	var hash [128]byte
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return 0, hash, nil
		}
		return 0, hash, err
	}
	v, _ := res["version"].(int64)
	h := asByteSlice(res["hash"])
	if len(h) == 128 {
		hash = *(*[128]byte)(h)
	}
	return uint64(v), hash, nil
}

func (s *MongoStore) DeleteAppStateVersion(ctx context.Context, name string) error {
	_, err := s.appStateVersionColl.DeleteOne(ctx, bson.M{"jid": s.JID, "name": name})
	return err
}

func (s *MongoStore) PutAppStateMutationMACs(ctx context.Context, name string, version uint64, mutations []store.AppStateMutationMAC) error {
	var docs []any
	for _, m := range mutations {
		docs = append(docs, bson.M{
			"jid":       s.JID,
			"name":      name,
			"version":   version,
			"index_mac": m.IndexMAC,
			"value_mac": m.ValueMAC,
		})
	}
	if len(docs) == 0 {
		return nil
	}
	_, err := s.appStateMutationColl.InsertMany(ctx, docs)
	return err
}

func (s *MongoStore) DeleteAppStateMutationMACs(ctx context.Context, name string, indexMACs [][]byte) error {
	filter := bson.M{
		"jid":       s.JID,
		"name":      name,
		"index_mac": bson.M{"$in": indexMACs},
	}
	_, err := s.appStateMutationColl.DeleteMany(ctx, filter)
	return err
}

func (s *MongoStore) GetAppStateMutationMAC(ctx context.Context, name string, indexMAC []byte) ([]byte, error) {
	var res bson.M
	err := s.appStateMutationColl.FindOne(ctx, bson.M{"jid": s.JID, "name": name, "index_mac": indexMAC}, options.FindOne().SetSort(bson.M{"version": -1})).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	mac := asByteSlice(res["value_mac"])
	return mac, nil
}

// ContactStore

func (s *MongoStore) PutPushName(ctx context.Context, user types.JID, pushName string) (bool, string, error) {
	s.contactCacheLock.Lock()
	defer s.contactCacheLock.Unlock()

	cached, err := s.getContact(ctx, user)
	if err != nil {
		return false, "", err
	}
	if cached.PushName != pushName {
		filter := bson.M{"our_jid": s.JID, "their_jid": user.String()}
		update := bson.M{"$set": bson.M{"push_name": pushName}}
		_, err = s.contactColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
		if err != nil {
			return false, "", err
		}
		prev := cached.PushName
		cached.PushName = pushName
		cached.Found = true
		return true, prev, nil
	}
	return false, "", nil
}

func (s *MongoStore) PutBusinessName(ctx context.Context, user types.JID, businessName string) (bool, string, error) {
	s.contactCacheLock.Lock()
	defer s.contactCacheLock.Unlock()

	cached, err := s.getContact(ctx, user)
	if err != nil {
		return false, "", err
	}
	if cached.BusinessName != businessName {
		filter := bson.M{"our_jid": s.JID, "their_jid": user.String()}
		update := bson.M{"$set": bson.M{"business_name": businessName}}
		_, err = s.contactColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
		if err != nil {
			return false, "", err
		}
		prev := cached.BusinessName
		cached.BusinessName = businessName
		cached.Found = true
		return true, prev, nil
	}
	return false, "", nil
}

func (s *MongoStore) PutContactName(ctx context.Context, user types.JID, fullName, firstName string) error {
	s.contactCacheLock.Lock()
	defer s.contactCacheLock.Unlock()

	cached, err := s.getContact(ctx, user)
	if err != nil {
		return err
	}
	if cached.FirstName != firstName || cached.FullName != fullName {
		filter := bson.M{"our_jid": s.JID, "their_jid": user.String()}
		update := bson.M{"$set": bson.M{"first_name": firstName, "full_name": fullName}}
		_, err = s.contactColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
		if err != nil {
			return err
		}
		cached.FirstName = firstName
		cached.FullName = fullName
		cached.Found = true
	}
	return nil
}

func (s *MongoStore) PutAllContactNames(ctx context.Context, contacts []store.ContactEntry) error {
	var models []mongo.WriteModel
	for _, ce := range contacts {
		filter := bson.M{"our_jid": s.JID, "their_jid": ce.JID.String()}
		update := bson.M{"$set": bson.M{"first_name": ce.FirstName, "full_name": ce.FullName}}
		models = append(models, mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update).SetUpsert(true))
	}
	if len(models) == 0 {
		return nil
	}
	_, err := s.contactColl.BulkWrite(ctx, models)
	if err == nil {
		s.contactCacheLock.Lock()
		s.contactCache = make(map[types.JID]*types.ContactInfo)
		s.contactCacheLock.Unlock()
	}
	return err
}

func (s *MongoStore) PutManyRedactedPhones(ctx context.Context, entries []store.RedactedPhoneEntry) error {
	var models []mongo.WriteModel
	for _, rpe := range entries {
		filter := bson.M{"our_jid": s.JID, "their_jid": rpe.JID.String()}
		update := bson.M{"$set": bson.M{"redacted_phone": rpe.RedactedPhone}}
		models = append(models, mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update).SetUpsert(true))
	}
	if len(models) == 0 {
		return nil
	}
	_, err := s.contactColl.BulkWrite(ctx, models)
	if err == nil {
		s.contactCacheLock.Lock()
		for _, e := range entries {
			delete(s.contactCache, e.JID)
		}
		s.contactCacheLock.Unlock()
	}
	return err
}

func getStringSafe(m bson.M, k string) string {
	if s, ok := m[k].(string); ok {
		return s
	}
	return ""
}

func (s *MongoStore) getContact(ctx context.Context, user types.JID) (*types.ContactInfo, error) {
	if cached, ok := s.contactCache[user]; ok {
		return cached, nil
	}
	var res bson.M
	err := s.contactColl.FindOne(ctx, bson.M{"our_jid": s.JID, "their_jid": user.String()}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			info := &types.ContactInfo{Found: false}
			s.contactCache[user] = info
			return info, nil
		}
		return nil, err
	}
	info := &types.ContactInfo{
		Found:         true,
		FirstName:     getStringSafe(res, "first_name"),
		FullName:      getStringSafe(res, "full_name"),
		PushName:      getStringSafe(res, "push_name"),
		BusinessName:  getStringSafe(res, "business_name"),
		RedactedPhone: getStringSafe(res, "redacted_phone"),
	}
	s.contactCache[user] = info
	return info, nil
}

func (s *MongoStore) GetContact(ctx context.Context, user types.JID) (types.ContactInfo, error) {
	s.contactCacheLock.Lock()
	info, err := s.getContact(ctx, user)
	s.contactCacheLock.Unlock()
	if err != nil {
		return types.ContactInfo{}, err
	}
	return *info, nil
}

func (s *MongoStore) GetAllContacts(ctx context.Context) (map[types.JID]types.ContactInfo, error) {
	cursor, err := s.contactColl.Find(ctx, bson.M{"our_jid": s.JID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	contacts := make(map[types.JID]types.ContactInfo)
	for cursor.Next(ctx) {
		var res bson.M
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		theirJid, _ := res["their_jid"].(string)
		jid, _ := types.ParseJID(theirJid)
		contacts[jid] = types.ContactInfo{
			Found:         true,
			FirstName:     getStringSafe(res, "first_name"),
			FullName:      getStringSafe(res, "full_name"),
			PushName:      getStringSafe(res, "push_name"),
			BusinessName:  getStringSafe(res, "business_name"),
			RedactedPhone: getStringSafe(res, "redacted_phone"),
		}
	}
	return contacts, nil
}

// ChatSettingsStore

func (s *MongoStore) PutMutedUntil(ctx context.Context, chat types.JID, mutedUntil time.Time) error {
	filter := bson.M{"our_jid": s.JID, "chat_id": chat.String()}
	update := bson.M{"$set": bson.M{"muted_until": mutedUntil.Unix()}}
	_, err := s.chatSettingsColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
	return err
}

func (s *MongoStore) PutPinned(ctx context.Context, chat types.JID, pinned bool) error {
	filter := bson.M{"our_jid": s.JID, "chat_id": chat.String()}
	update := bson.M{"$set": bson.M{"pinned": pinned}}
	_, err := s.chatSettingsColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
	return err
}

func (s *MongoStore) PutArchived(ctx context.Context, chat types.JID, archived bool) error {
	filter := bson.M{"our_jid": s.JID, "chat_id": chat.String()}
	update := bson.M{"$set": bson.M{"archived": archived}}
	_, err := s.chatSettingsColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
	return err
}

func (s *MongoStore) GetChatSettings(ctx context.Context, chat types.JID) (types.LocalChatSettings, error) {
	var res bson.M
	err := s.chatSettingsColl.FindOne(ctx, bson.M{"our_jid": s.JID, "chat_id": chat.String()}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return types.LocalChatSettings{}, nil
		}
		return types.LocalChatSettings{}, err
	}
	muted, _ := res["muted_until"].(int64)
	pinned, _ := res["pinned"].(bool)
	archived, _ := res["archived"].(bool)
	return types.LocalChatSettings{
		MutedUntil: time.Unix(muted, 0),
		Pinned:     pinned,
		Archived:   archived,
	}, nil
}

// MsgSecretStore

func (s *MongoStore) PutMessageSecrets(ctx context.Context, inserts []store.MessageSecretInsert) error {
	var docs []any
	for _, i := range inserts {
		docs = append(docs, bson.M{
			"our_jid":    s.JID,
			"chat_id":    i.Chat.String(),
			"sender_id":  i.Sender.String(),
			"message_id": i.ID,
			"secret":     i.Secret,
		})
	}
	if len(docs) == 0 {
		return nil
	}
	_, err := s.msgSecretColl.InsertMany(ctx, docs)
	return err
}

func (s *MongoStore) PutMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID, secret []byte) error {
	filter := bson.M{"our_jid": s.JID, "chat_id": chat.String(), "sender_id": sender.String(), "message_id": id}
	update := bson.M{"$set": bson.M{"secret": secret}}
	_, err := s.msgSecretColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
	return err
}

func (s *MongoStore) GetMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID) ([]byte, types.JID, error) {
	var res bson.M
	err := s.msgSecretColl.FindOne(ctx, bson.M{"our_jid": s.JID, "chat_id": chat.String(), "sender_id": sender.String(), "message_id": id}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, types.EmptyJID, nil
		}
		return nil, types.EmptyJID, err
	}
	secret := asByteSlice(res["secret"])
	// The SQL store also returns the sender JID, but it's the same as passed in.
	return secret, sender, nil
}

// PrivacyTokenStore

func (s *MongoStore) PutPrivacyTokens(ctx context.Context, tokens ...store.PrivacyToken) error {
	var models []mongo.WriteModel
	for _, t := range tokens {
		filter := bson.M{"our_jid": s.JID, "their_jid": t.User.String()}
		update := bson.M{"$set": bson.M{"token": t.Token, "timestamp": t.Timestamp.Unix()}}
		models = append(models, mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update).SetUpsert(true))
	}
	if len(models) == 0 {
		return nil
	}
	_, err := s.privacyTokenColl.BulkWrite(ctx, models)
	return err
}

func (s *MongoStore) GetPrivacyToken(ctx context.Context, user types.JID) (*store.PrivacyToken, error) {
	var res bson.M
	err := s.privacyTokenColl.FindOne(ctx, bson.M{"our_jid": s.JID, "their_jid": user.String()}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	token := asByteSlice(res["token"])
	ts, _ := res["timestamp"].(int64)
	return &store.PrivacyToken{
		User:      user,
		Token:     token,
		Timestamp: time.Unix(ts, 0),
	}, nil
}

// EventBuffer

func (s *MongoStore) GetBufferedEvent(ctx context.Context, ciphertextHash [32]byte) (*store.BufferedEvent, error) {
	var res bson.M
	err := s.eventBufferColl.FindOne(ctx, bson.M{"our_jid": s.JID, "ciphertext_hash": ciphertextHash[:]}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	plaintext := asByteSlice(res["plaintext"])
	insertTs, _ := res["insert_time"].(int64)
	serverTs, _ := res["server_time"].(int64)
	return &store.BufferedEvent{
		Plaintext:  plaintext,
		InsertTime: time.Unix(0, insertTs),
		ServerTime: time.Unix(0, serverTs),
	}, nil
}

func (s *MongoStore) PutBufferedEvent(ctx context.Context, ciphertextHash [32]byte, plaintext []byte, serverTimestamp time.Time) error {
	filter := bson.M{"our_jid": s.JID, "ciphertext_hash": ciphertextHash[:]}
	update := bson.M{
		"$set": bson.M{
			"plaintext":   plaintext,
			"insert_time": time.Now().UnixNano(),
			"server_time": serverTimestamp.UnixNano(),
		},
	}
	_, err := s.eventBufferColl.UpdateOne(ctx, filter, update, options.UpdateOne().SetUpsert(true))
	return err
}

func (s *MongoStore) DoDecryptionTxn(ctx context.Context, fn func(context.Context) error) error {
	// MongoDB transactions are complex and require a replica set.
	// For now, let's just run the function.
	return fn(ctx)
}

func (s *MongoStore) ClearBufferedEventPlaintext(ctx context.Context, ciphertextHash [32]byte) error {
	filter := bson.M{"our_jid": s.JID, "ciphertext_hash": ciphertextHash[:]}
	update := bson.M{"$set": bson.M{"plaintext": nil}}
	_, err := s.eventBufferColl.UpdateOne(ctx, filter, update)
	return err
}

func (s *MongoStore) DeleteOldBufferedHashes(ctx context.Context) error {
	// Delete older than 24 hours
	filter := bson.M{"our_jid": s.JID, "insert_time": bson.M{"$lt": time.Now().Add(-24 * time.Hour).UnixNano()}}
	_, err := s.eventBufferColl.DeleteMany(ctx, filter)
	return err
}

func (s *MongoStore) GetOutgoingEvent(ctx context.Context, chatJID, altChatJID types.JID, id types.MessageID) (string, []byte, error) {
	filter := bson.M{
		"our_jid": s.JID,
		"chat_id": bson.M{"$in": []string{chatJID.String(), altChatJID.String()}},
		"message_id": id,
	}
	var res bson.M
	err := s.outgoingEventColl.FindOne(ctx, filter).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", nil, nil
		}
		return "", nil, err
	}
	format, _ := res["format"].(string)
	plaintext := asByteSlice(res["plaintext"])
	return format, plaintext, nil
}

func (s *MongoStore) AddOutgoingEvent(ctx context.Context, chatJID types.JID, id types.MessageID, format string, plaintext []byte) error {
	doc := bson.M{
		"our_jid":     s.JID,
		"chat_id":     chatJID.String(),
		"message_id":  id,
		"format":      format,
		"plaintext":   plaintext,
		"insert_time": time.Now().UnixNano(),
	}
	_, err := s.outgoingEventColl.InsertOne(ctx, doc)
	return err
}

func (s *MongoStore) DeleteOldOutgoingEvents(ctx context.Context) error {
	filter := bson.M{"our_jid": s.JID, "insert_time": bson.M{"$lt": time.Now().Add(-24 * time.Hour).UnixNano()}}
	_, err := s.outgoingEventColl.DeleteMany(ctx, filter)
	return err
}
