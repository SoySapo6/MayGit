// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package files

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"

	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/gitrepo"
	"code.gitea.io/gitea/modules/setting"
	api "code.gitea.io/gitea/modules/structs"
	"code.gitea.io/gitea/modules/util"
)

// ErrSHANotFound represents a "SHADoesNotMatch" kind of error.
type ErrSHANotFound struct {
	SHA string
}

// IsErrSHANotFound checks if an error is a ErrSHANotFound.
func IsErrSHANotFound(err error) bool {
	_, ok := err.(ErrSHANotFound)
	return ok
}

func (err ErrSHANotFound) Error() string {
	return fmt.Sprintf("sha not found [%s]", err.SHA)
}

func (err ErrSHANotFound) Unwrap() error {
	return util.ErrNotExist
}

// GetTreeBySHA get the GitTreeResponse of a repository using a sha hash.
func GetTreeBySHA(ctx context.Context, repo *repo_model.Repository, gitRepo *git.Repository, sha string, page, perPage int, recursive bool) (*api.GitTreeResponse, error) {
	gitTree, err := gitRepo.GetTree(sha)
	if err != nil || gitTree == nil {
		return nil, ErrSHANotFound{ // TODO: this error has never been catch outside of this function
			SHA: sha,
		}
	}
	tree := new(api.GitTreeResponse)
	tree.SHA = gitTree.ResolvedID.String()
	tree.URL = repo.APIURL() + "/git/trees/" + url.PathEscape(tree.SHA)
	var entries git.Entries
	if recursive {
		entries, err = gitTree.ListEntriesRecursiveWithSize()
	} else {
		entries, err = gitTree.ListEntries()
	}
	if err != nil {
		return nil, err
	}
	apiURL := repo.APIURL()
	apiURLLen := len(apiURL)
	objectFormat := git.ObjectFormatFromName(repo.ObjectFormatName)
	hashLen := objectFormat.FullLength()

	const gitBlobsPath = "/git/blobs/"
	blobURL := make([]byte, apiURLLen+hashLen+len(gitBlobsPath))
	copy(blobURL, apiURL)
	copy(blobURL[apiURLLen:], []byte(gitBlobsPath))

	const gitTreePath = "/git/trees/"
	treeURL := make([]byte, apiURLLen+hashLen+len(gitTreePath))
	copy(treeURL, apiURL)
	copy(treeURL[apiURLLen:], []byte(gitTreePath))

	// copyPos is at the start of the hash
	copyPos := len(treeURL) - hashLen

	if perPage <= 0 || perPage > setting.API.DefaultGitTreesPerPage {
		perPage = setting.API.DefaultGitTreesPerPage
	}
	if page <= 0 {
		page = 1
	}
	tree.Page = page
	tree.TotalCount = len(entries)
	rangeStart := perPage * (page - 1)
	if rangeStart >= len(entries) {
		return tree, nil
	}
	var rangeEnd int
	if len(entries) > perPage {
		tree.Truncated = true
	}
	if rangeStart+perPage < len(entries) {
		rangeEnd = rangeStart + perPage
	} else {
		rangeEnd = len(entries)
	}
	tree.Entries = make([]api.GitEntry, rangeEnd-rangeStart)
	for e := rangeStart; e < rangeEnd; e++ {
		i := e - rangeStart

		tree.Entries[i].Path = entries[e].Name()
		tree.Entries[i].Mode = fmt.Sprintf("%06o", entries[e].Mode())
		tree.Entries[i].Type = entries[e].Type()
		tree.Entries[i].Size = entries[e].Size()
		tree.Entries[i].SHA = entries[e].ID.String()

		if entries[e].IsDir() {
			copy(treeURL[copyPos:], entries[e].ID.String())
			tree.Entries[i].URL = string(treeURL)
		} else if entries[e].IsSubModule() {
			// In Github Rest API Version=2022-11-28, if a tree entry is a submodule,
			// its url will be returned as an empty string.
			// So the URL will be set to "" here.
			tree.Entries[i].URL = ""
		} else {
			copy(blobURL[copyPos:], entries[e].ID.String())
			tree.Entries[i].URL = string(blobURL)
		}
	}
	return tree, nil
}

type TreeEntry struct {
	Name     string       `json:"name"`
	IsFile   bool         `json:"isFile"`
	Path     string       `json:"path"`
	Children []*TreeEntry `json:"children"`
}

func GetTreeList(ctx context.Context, repo *repo_model.Repository, treePath string, ref git.RefName, recursive bool) ([]*TreeEntry, error) {
	if repo.IsEmpty {
		return nil, nil
	}
	if ref == "" {
		ref = git.RefNameFromBranch(repo.DefaultBranch)
	}

	// Check that the path given in opts.treePath is valid (not a git path)
	cleanTreePath := CleanUploadFileName(treePath)
	if cleanTreePath == "" && treePath != "" {
		return nil, ErrFilenameInvalid{
			Path: treePath,
		}
	}
	treePath = cleanTreePath

	gitRepo, closer, err := gitrepo.RepositoryFromContextOrOpen(ctx, repo)
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	// Get the commit object for the ref
	commit, err := gitRepo.GetCommit(ref.String())
	if err != nil {
		return nil, err
	}

	entry, err := commit.GetTreeEntryByPath(treePath)
	if err != nil {
		return nil, err
	}

	// If the entry is a file, we return a FileContentResponse object
	if entry.Type() != "tree" {
		return nil, fmt.Errorf("%s is not a tree", treePath)
	}

	gitTree, err := commit.SubTree(treePath)
	if err != nil {
		return nil, err
	}
	var entries git.Entries
	if recursive {
		entries, err = gitTree.ListEntriesRecursiveFast()
	} else {
		entries, err = gitTree.ListEntries()
	}
	if err != nil {
		return nil, err
	}

	var treeList []*TreeEntry
	mapTree := make(map[string][]*TreeEntry)
	for _, e := range entries {
		subTreePath := path.Join(treePath, e.Name())

		if strings.Contains(e.Name(), "/") {
			mapTree[path.Dir(e.Name())] = append(mapTree[path.Dir(e.Name())], &TreeEntry{
				Name:   path.Base(e.Name()),
				IsFile: e.Mode() != git.EntryModeTree,
				Path:   subTreePath,
			})
		} else {
			treeList = append(treeList, &TreeEntry{
				Name:   e.Name(),
				IsFile: e.Mode() != git.EntryModeTree,
				Path:   subTreePath,
			})
		}
	}

	for _, tree := range treeList {
		if !tree.IsFile {
			tree.Children = mapTree[tree.Path]
		}
	}

	return treeList, nil
}

// GetTreeInformation returns the first level directories and files and all the trees of the path to treePath.
// If treePath is a directory, list all subdirectories and files of treePath.
func GetTreeInformation(ctx context.Context, repo *repo_model.Repository, treePath string, ref git.RefName) ([]*TreeEntry, error) {
	if repo.IsEmpty {
		return nil, nil
	}
	if ref == "" {
		ref = git.RefNameFromBranch(repo.DefaultBranch)
	}

	// Check that the path given in opts.treePath is valid (not a git path)
	cleanTreePath := CleanUploadFileName(treePath)
	if cleanTreePath == "" && treePath != "" {
		return nil, ErrFilenameInvalid{
			Path: treePath,
		}
	}
	treePath = cleanTreePath

	gitRepo, closer, err := gitrepo.RepositoryFromContextOrOpen(ctx, repo)
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	// Get the commit object for the ref
	commit, err := gitRepo.GetCommit(ref.String())
	if err != nil {
		return nil, err
	}

	// get root entries
	rootEntry, err := commit.GetTreeEntryByPath("")
	if err != nil {
		return nil, err
	}
	rootEntries, err := rootEntry.Tree().ListEntries()
	if err != nil {
		return nil, err
	}

	var treeList []*TreeEntry
	var parentEntry *TreeEntry
	fields := strings.SplitN(treePath, "/", 2)
	for _, rootEntry := range rootEntries {
		treeEntry := &TreeEntry{
			Name:   rootEntry.Name(),
			IsFile: rootEntry.Mode() != git.EntryModeTree,
			Path:   rootEntry.Name(),
		}
		treeList = append(treeList, treeEntry)
		if fields[0] == rootEntry.Name() {
			parentEntry = treeEntry
		}
	}

	if treePath == "" || parentEntry == nil {
		return treeList, nil
	}

	listEntry, err := commit.GetTreeEntryByPath(treePath)
	if err != nil {
		return nil, err
	}

	dir := treePath
	// list current entry or parent entry if it's a file's children
	// If the entry is a file, we return a FileContentResponse object
	if listEntry.IsRegular() {
		dir = path.Dir(treePath)
		if dir == "" {
			return treeList, nil
		}
		listEntry, err = commit.GetTreeEntryByPath(dir)
		if err != nil {
			return nil, err
		}
	}

	for i := 1; i < len(fields); i++ {
		parentEntry.Children = []*TreeEntry{
			{
				Name:   fields[i],
				IsFile: false,
				Path:   path.Join(fields[:i+1]...),
			},
		}
		parentEntry = parentEntry.Children[0]
	}

	entries, err := listEntry.Tree().ListEntries()
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		parentEntry.Children = append(parentEntry.Children, &TreeEntry{
			Name:   entry.Name(),
			IsFile: entry.Mode() != git.EntryModeTree,
			Path:   path.Join(treePath, entry.Name()),
		})
	}
	return treeList, nil
}
