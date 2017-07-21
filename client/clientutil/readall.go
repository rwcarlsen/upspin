// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package clientutil implements common utilities shared by clients and those
// who act as clients, such as a DirServer being a client of a StoreServer.
package clientutil // import "upspin.io/client/clientutil"

import (
	"strings"

	"upspin.io/access"
	"upspin.io/bind"
	"upspin.io/errors"
	"upspin.io/metric"
	"upspin.io/pack"
	"upspin.io/path"
	"upspin.io/upspin"
)

// ReadAll reads the entire contents of a DirEntry. The reader must have
// the necessary keys loaded in the config to unpack the cipher if the entry
// is encrypted.
func ReadAll(cfg upspin.Config, entry *upspin.DirEntry) ([]byte, error) {
	const op = "client/clientutil.ReadAll"

	if entry.IsLink() {
		return nil, errors.E(op, entry.Name, errors.Invalid, errors.Str("can't read a link entry"))
	}
	if entry.IsIncomplete() {
		return nil, errors.E(op, entry.Name, errors.Permission)
	}
	if access.IsAccessFile(entry.SignedName) {
		// Access files must be written by their owners only.
		p, _ := path.Parse(entry.SignedName)
		if p.User() != entry.Writer {
			return nil, errors.E(errors.Invalid, p.User(), errors.Str("writer of Access file does not match owner"))
		}
	}

	var data []byte
	packer := pack.Lookup(entry.Packing)
	if packer == nil {
		return nil, errors.E(op, entry.Name, errors.Errorf("unrecognized Packing %d", entry.Packing))
	}
	bu, err := packer.Unpack(cfg, entry)
	if err != nil {
		return nil, errors.E(op, entry.Name, err) // Showstopper.
	}
	for {
		block, ok := bu.NextBlock()
		if !ok {
			break // EOF
		}
		// block is known valid as per valid.DirEntry above.

		cipher, err := ReadLocation(cfg, block.Location)
		if err != nil {
			return nil, errors.E(op, err)
		}
		clear, err := bu.Unpack(cipher)
		if err != nil {
			return nil, errors.E(op, entry.Name, err)
		}
		data = append(data, clear...) // TODO: Could avoid a copy if only one block.
	}
	return data, nil
}

// ReadLocation uses the provided Config to fetch the contents of the given
// Location, following any StoreServer.Get redirects.
func ReadLocation(cfg upspin.Config, loc upspin.Location) ([]byte, error) {
	const op = "client/clientutil.ReadLocation"

	// firstError remembers the first error we saw.
	// If we fail completely we return it.
	var firstError error
	// isError reports whether err is non-nil and remembers it if it is.
	isError := func(err error) bool {
		if err == nil {
			return false
		}
		if firstError == nil {
			firstError = err
		}
		return true
	}

	// knownLocs stores the known Locations for this block. Value is
	// ignored.
	knownLocs := make(map[upspin.Location]bool)
	// Get the data for this block.
	// where is the list of locations to examine. It is updated in the loop.
	where := []upspin.Location{loc}
	for i := 0; i < len(where); i++ { // Not range loop - where changes as we run.
		loc := where[i]
		store, err := bind.StoreServer(cfg, loc.Endpoint)
		if isError(err) {
			continue
		}
		data, _, locs, err := store.Get(loc.Reference)
		if isError(err) {
			continue // locs guaranteed to be nil.
		}
		if locs == nil && err == nil {
			return data, nil
		}
		// Add new locs to the list. Skip ones already there - they've been processed.
		for _, newLoc := range locs {
			if _, found := knownLocs[newLoc]; !found {
				where = append(where, newLoc)
				knownLocs[newLoc] = true
			}
		}
	}

	// If we arrive here, we have failed to find a block.
	if firstError != nil {
		return nil, errors.E(op, firstError)
	}
	return nil, errors.E(op, errors.IO, errors.Errorf("data for location %v not found on any store server", loc))
}

// GetReaders returns the list of intended readers for the given name
// according to the Access file.
// If the Access file cannot be read because of lack of permissions,
// it returns the owner of the file (but only if we are not the owner).
func GetReaders(cfg upspin.Config, name upspin.PathName, accessEntry *upspin.DirEntry) ([]upspin.UserName, error) {
	if accessEntry == nil {
		// No Access file present, therefore we must be the owner.
		return nil, nil
	}
	accessData, err := c.Get(accessEntry.Name)
	if errors.Match(errors.E(errors.NotExist), err) || errors.Match(errors.E(errors.Permission), err) || errors.Match(errors.E(errors.Private), err) {
		// If we failed to get the Access file for access-control
		// reasons, then we must not have read access and thus
		// cannot know the list of readers.
		// Instead, just return the owner as the only reader.
		parsed, err := path.Parse(name)
		if err != nil {
			return nil, err
		}
		owner := parsed.User()
		if owner == c.config.UserName() {
			// We are the owner, but the caller always
			// adds the us, so return an empty list.
			return nil, nil
		}
		return []upspin.UserName{owner}, nil
	} else if err != nil {
		// We failed to fetch the Access file for some unexpected reason,
		// so bubble the error up.
		return nil, err
	}
	acc, err := access.Parse(accessEntry.Name, accessData)
	if err != nil {
		return nil, err
	}
	readers, err := acc.Users(access.Read, c.Get)
	if err != nil {
		return nil, err
	}
	return readers, nil
}

// A LookupFn is called by the evaluation loop in lookup. It calls the underlying
// DirServer operation and may return ErrFollowLink, some other error, or success.
// If it is ErrFollowLink, lookup will step through the link and try again.
type LookupFn func(upspin.DirServer, *upspin.DirEntry, *metric.Span) (*upspin.DirEntry, error)

func getDirServer(cfg upspin.Config, op string, path upspin.PathName) (upspin.DirServer, error) {
	parsed, err := path.Parse(name)
	if err != nil {
		return nil, errors.E(op, err)
	}
	dir, err := bind.DirServerFor(cfg, parsed.User())
	if err != nil {
		return nil, errors.E(op, err)
	}
	return dir, nil
}

func WhichAccessLookupFn(dir upspin.DirServer, entry *upspin.DirEntry, s *metric.Span) (*upspin.DirEntry, error) {
	defer s.StartSpan("dir.WhichAccess").End()
	whichEntry, err := dir.WhichAccess(entry.Name)
	if err != nil {
		return whichEntry, err
	}
	return whichEntry, validateWhichAccess(entry.Name, whichEntry)
}

// Lookup returns the DirEntry referenced by the argument entry,
// evaluated by following any links in the path except maybe for one detail:
// The boolean states whether, if the final path element is a link,
// that link should be evaluated. If true, the returned entry represents
// the target of the link. If false, it represents the link itself.
//
// In some cases, such as when called from Lookup, the argument
// entry might contain nothing but a name, but it must always have a name.
// The call may overwrite the fields of the argument DirEntry,
// updating its name as it crosses links.
// The returned DirEntries on success are the result of completing
// the operation followed by the argument to the last successful
// call to fn, which for instance will contain the actual path that
// resulted in a successful call to WhichAccess.
func Lookup(cfg upspin.Config, op string, entry *upspin.DirEntry, fn LookupFn, followFinal bool, s *metric.Span) (resultEntry, finalSuccessfulEntry *upspin.DirEntry, err error) {
	ss := s.StartSpan("Client.Lookup")
	defer ss.End()

	// As we run, we want to maintain the incoming DirEntry to track the name,
	// leaving the rest alone. As the fn will return a newly allocated entry,
	// after each link we update the entry to achieve this.
	originalName := entry.Name
	var prevEntry *upspin.DirEntry
	copied := false // Do we need to allocate a new entry to modify its name?
	for loop := 0; loop < upspin.MaxLinkHops; loop++ {
		parsed, err := path.Parse(entry.Name)
		if err != nil {
			return nil, nil, errors.E(op, err)
		}
		dir, err := getDirServer(cfg, "Client.DirServer", parsed.Path())
		if err != nil {
			return nil, nil, errors.E(op, err)
		}
		resultEntry, err := fn(dir, entry, ss)
		if err == nil {
			return resultEntry, entry, nil
		}
		if prevEntry != nil && errors.Match(errors.E(errors.NotExist), err) {
			return resultEntry, nil, errors.E(errors.BrokenLink, prevEntry.Name, err)
		}
		prevEntry = resultEntry
		if err != upspin.ErrFollowLink {
			return resultEntry, nil, errors.E(op, err)
		}
		// We have a link.
		// First, allocate a new entry if necessary so we don't overwrite user's memory.
		if !copied {
			tmp := *entry
			entry = &tmp
			copied = true
		}
		// Take the prefix of the result entry and substitute that section of the existing name.
		parsedResult, err := path.Parse(resultEntry.Name)
		if err != nil {
			return nil, nil, errors.E(op, err)
		}
		resultPath := parsedResult.Path()
		// The result entry's name must be a prefix of the name we're looking up.
		if !strings.HasPrefix(parsed.String(), string(resultPath)) {
			return nil, nil, errors.E(op, resultPath, errors.Internal, errors.Str("link path not prefix"))
		}
		// Update the entry to have the new Name field.
		if resultPath == parsed.Path() {
			// We're on the last element. We may be done.
			if followFinal {
				entry.Name = resultEntry.Link
			} else {
				// Yes, we are done. Return this entry, which is a link.
				return resultEntry, entry, nil
			}
		} else {
			entry.Name = path.Join(resultEntry.Link, string(parsed.Path()[len(resultPath):]))
		}
	}
	return nil, nil, errors.E(op, errors.IO, originalName, errors.Str("link loop"))
}
