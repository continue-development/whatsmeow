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
	"sync"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"


	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

type CachedLIDMap struct {
	coll *mongo.Collection

	pnToLIDCache map[string]string
	lidToPNCache map[string]string
	cacheFilled  bool
	lidCacheLock sync.RWMutex
}

var _ store.LIDStore = (*CachedLIDMap)(nil)

func NewCachedLIDMap(db *mongo.Database) *CachedLIDMap {
	return &CachedLIDMap{
		coll: db.Collection("whatsmeow_lid_map"),

		pnToLIDCache: make(map[string]string),
		lidToPNCache: make(map[string]string),
	}
}

func (s *CachedLIDMap) FillCache(ctx context.Context) error {
	s.lidCacheLock.Lock()
	defer s.lidCacheLock.Unlock()

	cursor, err := s.coll.Find(ctx, bson.M{})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var res bson.M
		if err := cursor.Decode(&res); err != nil {
			return err
		}
		lid, _ := res["lid"].(string)
		pn, _ := res["pn"].(string)
		s.pnToLIDCache[pn] = lid
		s.lidToPNCache[lid] = pn
	}
	s.cacheFilled = true
	return nil
}

func (s *CachedLIDMap) getLIDMapping(ctx context.Context, source types.JID, targetServer, queryKey string, sourceToTarget, targetToSource map[string]string) (types.JID, error) {
	s.lidCacheLock.RLock()
	targetUser, ok := sourceToTarget[source.User]
	cacheFilled := s.cacheFilled
	s.lidCacheLock.RUnlock()
	if ok || cacheFilled {
		if targetUser == "" {
			return types.JID{}, nil
		}
		return types.JID{User: targetUser, Device: source.Device, Server: targetServer}, nil
	}

	s.lidCacheLock.Lock()
	defer s.lidCacheLock.Unlock()

	var res bson.M
	err := s.coll.FindOne(ctx, bson.M{queryKey: source.User}).Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			sourceToTarget[source.User] = ""
			return types.JID{}, nil
		}
		return types.JID{}, err
	}
	
	targetUser, _ = res["lid"].(string) // default to lid if looking for pn
	if queryKey == "lid" {
		targetUser, _ = res["pn"].(string)
	}
	
	sourceToTarget[source.User] = targetUser
	if targetUser != "" {
		targetToSource[targetUser] = source.User
		return types.JID{User: targetUser, Device: source.Device, Server: targetServer}, nil
	}
	return types.JID{}, nil
}

func (s *CachedLIDMap) GetLIDForPN(ctx context.Context, pn types.JID) (types.JID, error) {
	if pn.Server != types.DefaultUserServer {
		return types.JID{}, fmt.Errorf("invalid GetLIDForPN call with non-PN JID %s", pn)
	}
	return s.getLIDMapping(ctx, pn, types.HiddenUserServer, "pn", s.pnToLIDCache, s.lidToPNCache)
}

func (s *CachedLIDMap) GetPNForLID(ctx context.Context, lid types.JID) (types.JID, error) {
	if lid.Server != types.HiddenUserServer {
		return types.JID{}, fmt.Errorf("invalid GetPNForLID call with non-LID JID %s", lid)
	}
	return s.getLIDMapping(ctx, lid, types.DefaultUserServer, "lid", s.lidToPNCache, s.pnToLIDCache)
}

func (s *CachedLIDMap) GetManyLIDsForPNs(ctx context.Context, pns []types.JID) (map[types.JID]types.JID, error) {
	if len(pns) == 0 {
		return nil, nil
	}

	result := make(map[types.JID]types.JID, len(pns))
	s.lidCacheLock.RLock()
	missingPNs := make([]string, 0, len(pns))
	missingPNDevices := make(map[string][]types.JID)
	for _, pn := range pns {
		if pn.Server != types.DefaultUserServer {
			continue
		}
		if lidUser, ok := s.pnToLIDCache[pn.User]; ok && lidUser != "" {
			result[pn] = types.JID{User: lidUser, Device: pn.Device, Server: types.HiddenUserServer}
		} else if !s.cacheFilled {
			missingPNs = append(missingPNs, pn.User)
			missingPNDevices[pn.User] = append(missingPNDevices[pn.User], pn)
		}
	}
	s.lidCacheLock.RUnlock()

	if len(missingPNs) == 0 {
		return result, nil
	}

	s.lidCacheLock.Lock()
	defer s.lidCacheLock.Unlock()

	cursor, err := s.coll.Find(ctx, bson.M{"pn": bson.M{"$in": missingPNs}})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var res bson.M
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		lid, _ := res["lid"].(string)
		pn, _ := res["pn"].(string)
		s.pnToLIDCache[pn] = lid
		s.lidToPNCache[lid] = pn

		for _, dev := range missingPNDevices[pn] {
			lidDev := dev
			lidDev.Server = types.HiddenUserServer
			lidDev.User = lid
			result[dev] = lidDev.ToNonAD()
		}
	}
	return result, nil
}

func (s *CachedLIDMap) PutLIDMapping(ctx context.Context, lid, pn types.JID) error {
	if lid.Server != types.HiddenUserServer || pn.Server != types.DefaultUserServer {
		return fmt.Errorf("invalid PutLIDMapping call %s/%s", lid, pn)
	}
	s.lidCacheLock.Lock()
	defer s.lidCacheLock.Unlock()

	cachedLID, ok := s.pnToLIDCache[pn.User]
	if ok && cachedLID == lid.User {
		return nil
	}

	_, err := s.coll.DeleteMany(ctx, bson.M{"$or": []bson.M{{"lid": lid.User}, {"pn": pn.User}}})
	if err != nil {
		return err
	}

	_, err = s.coll.InsertOne(ctx, bson.M{"lid": lid.User, "pn": pn.User})
	if err != nil {
		return err
	}

	s.pnToLIDCache[pn.User] = lid.User
	s.lidToPNCache[lid.User] = pn.User
	return nil
}

func (s *CachedLIDMap) PutManyLIDMappings(ctx context.Context, mappings []store.LIDMapping) error {
	s.lidCacheLock.Lock()
	defer s.lidCacheLock.Unlock()

	var models []mongo.WriteModel
	for _, m := range mappings {
		if m.LID.Server != types.HiddenUserServer || m.PN.Server != types.DefaultUserServer {
			continue
		}
		cachedLID, ok := s.pnToLIDCache[m.PN.User]
		if ok && cachedLID == m.LID.User {
			continue
		}

		// Delete existing entries for this LID or PN to ensure uniqueness (simple approach)
		models = append(models, mongo.NewDeleteManyModel().SetFilter(bson.M{"$or": []bson.M{{"lid": m.LID.User}, {"pn": m.PN.User}}}))
		models = append(models, mongo.NewInsertOneModel().SetDocument(bson.M{"lid": m.LID.User, "pn": m.PN.User}))
	}

	if len(models) == 0 {
		return nil
	}

	_, err := s.coll.BulkWrite(ctx, models)
	if err == nil {
		// Just clear cache for simplicity if we did bulk write
		s.pnToLIDCache = make(map[string]string)
		s.lidToPNCache = make(map[string]string)
		s.cacheFilled = false
	}
	return err
}
