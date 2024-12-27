// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issues_test

import (
	"context"
	"fmt"
	"testing"

	"code.gitea.io/gitea/models/db"
	issues_model "code.gitea.io/gitea/models/issues"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/unittest"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/references"
	"code.gitea.io/gitea/modules/util"

	"github.com/stretchr/testify/assert"
)

func TestXRef_AddCrossReferences(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())

	// Issue #1 to test against
	itarget := testCreateIssue(t, 1, 2, "title1", "content1", false)

	// PR to close issue #1
	content := fmt.Sprintf("content2, closes #%d", itarget.Index)
	pr := testCreateIssue(t, 1, 2, "title2", content, true)
	ref := unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: itarget.ID, RefIssueID: pr.ID, RefCommentID: 0})
	assert.Equal(t, issues_model.CommentTypePullRef, ref.Type)
	assert.Equal(t, pr.RepoID, ref.RefRepoID)
	assert.True(t, ref.RefIsPull)
	assert.Equal(t, references.XRefActionCloses, ref.RefAction)

	// Comment on PR to reopen issue #1
	content = fmt.Sprintf("content2, reopens #%d", itarget.Index)
	c := testCreateComment(t, 2, pr.ID, content)
	ref = unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: itarget.ID, RefIssueID: pr.ID, RefCommentID: c.ID})
	assert.Equal(t, issues_model.CommentTypeCommentRef, ref.Type)
	assert.Equal(t, pr.RepoID, ref.RefRepoID)
	assert.True(t, ref.RefIsPull)
	assert.Equal(t, references.XRefActionReopens, ref.RefAction)

	// Issue mentioning issue #1
	content = fmt.Sprintf("content3, mentions #%d", itarget.Index)
	i := testCreateIssue(t, 1, 2, "title3", content, false)
	ref = unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: itarget.ID, RefIssueID: i.ID, RefCommentID: 0})
	assert.Equal(t, issues_model.CommentTypeIssueRef, ref.Type)
	assert.Equal(t, pr.RepoID, ref.RefRepoID)
	assert.False(t, ref.RefIsPull)
	assert.Equal(t, references.XRefActionNone, ref.RefAction)

	// Issue #4 to test against
	itarget = testCreateIssue(t, 3, 3, "title4", "content4", false)

	// Cross-reference to issue #4 by admin
	content = fmt.Sprintf("content5, mentions org3/repo3#%d", itarget.Index)
	i = testCreateIssue(t, 2, 1, "title5", content, false)
	ref = unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: itarget.ID, RefIssueID: i.ID, RefCommentID: 0})
	assert.Equal(t, issues_model.CommentTypeIssueRef, ref.Type)
	assert.Equal(t, i.RepoID, ref.RefRepoID)
	assert.False(t, ref.RefIsPull)
	assert.Equal(t, references.XRefActionNone, ref.RefAction)

	// Cross-reference to issue #4 with no permission
	content = fmt.Sprintf("content6, mentions org3/repo3#%d", itarget.Index)
	i = testCreateIssue(t, 4, 5, "title6", content, false)
	unittest.AssertNotExistsBean(t, &issues_model.Comment{IssueID: itarget.ID, RefIssueID: i.ID, RefCommentID: 0})
}

// changeIssueTitle changes the title of this issue, as the given user.
func changeIssueTitle(ctx context.Context, issue *issues_model.Issue, doer *user_model.User, oldTitle string) (err error) {
	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	issue.Title = util.EllipsisDisplayString(issue.Title, 255)
	if err = issues_model.UpdateIssueCols(ctx, issue, "name"); err != nil {
		return fmt.Errorf("updateIssueCols: %w", err)
	}

	if err = issue.LoadRepo(ctx); err != nil {
		return fmt.Errorf("loadRepo: %w", err)
	}

	opts := &issues_model.CreateCommentOptions{
		Type:     issues_model.CommentTypeChangeTitle,
		Doer:     doer,
		Repo:     issue.Repo,
		Issue:    issue,
		OldTitle: oldTitle,
		NewTitle: issue.Title,
	}
	if _, err = issues_model.CreateComment(ctx, opts); err != nil {
		return fmt.Errorf("createComment: %w", err)
	}
	if err = issue.AddCrossReferences(ctx, doer, true); err != nil {
		return err
	}

	return committer.Commit()
}

func TestXRef_NeuterCrossReferences(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())

	// Issue #1 to test against
	itarget := testCreateIssue(t, 1, 2, "title1", "content1", false)

	// Issue mentioning issue #1
	title := fmt.Sprintf("title2, mentions #%d", itarget.Index)
	i := testCreateIssue(t, 1, 2, title, "content2", false)
	ref := unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: itarget.ID, RefIssueID: i.ID, RefCommentID: 0})
	assert.Equal(t, issues_model.CommentTypeIssueRef, ref.Type)
	assert.Equal(t, references.XRefActionNone, ref.RefAction)

	d := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	i.Title = "title2, no mentions"
	assert.NoError(t, changeIssueTitle(db.DefaultContext, i, d, title))

	ref = unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: itarget.ID, RefIssueID: i.ID, RefCommentID: 0})
	assert.Equal(t, issues_model.CommentTypeIssueRef, ref.Type)
	assert.Equal(t, references.XRefActionNeutered, ref.RefAction)
}

// newPullRequest creates new pull request with labels for repository.
func newPullRequest(ctx context.Context, repo *repo_model.Repository, issue *issues_model.Issue, labelIDs []int64, uuids []string, pr *issues_model.PullRequest) (err error) {
	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	idx, err := db.GetNextResourceIndex(ctx, "issue_index", repo.ID)
	if err != nil {
		return fmt.Errorf("generate pull request index failed: %w", err)
	}

	issue.Index = idx

	if err = issues_model.NewIssueWithIndex(ctx, issue.Poster, issues_model.NewIssueOptions{
		Repo:        repo,
		Issue:       issue,
		LabelIDs:    labelIDs,
		Attachments: uuids,
		IsPull:      true,
	}); err != nil {
		if repo_model.IsErrUserDoesNotHaveAccessToRepo(err) || issues_model.IsErrNewIssueInsert(err) {
			return err
		}
		return fmt.Errorf("newIssue: %w", err)
	}

	pr.Index = issue.Index
	pr.BaseRepo = repo
	pr.IssueID = issue.ID
	if err = db.Insert(ctx, pr); err != nil {
		return fmt.Errorf("insert pull repo: %w", err)
	}

	if err = committer.Commit(); err != nil {
		return fmt.Errorf("Commit: %w", err)
	}

	return nil
}

func TestXRef_ResolveCrossReferences(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())

	d := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	i1 := testCreateIssue(t, 1, 2, "title1", "content1", false)
	i2 := testCreateIssue(t, 1, 2, "title2", "content2", false)
	i3 := testCreateIssue(t, 1, 2, "title3", "content3", false)
	_, err := issues_model.CloseIssue(db.DefaultContext, i3, d)
	assert.NoError(t, err)

	pr := testCreatePR(t, 1, 2, "titlepr", fmt.Sprintf("closes #%d", i1.Index))
	rp := unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: i1.ID, RefIssueID: pr.Issue.ID, RefCommentID: 0})

	c1 := testCreateComment(t, 2, pr.Issue.ID, fmt.Sprintf("closes #%d", i2.Index))
	r1 := unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: i2.ID, RefIssueID: pr.Issue.ID, RefCommentID: c1.ID})

	// Must be ignored
	c2 := testCreateComment(t, 2, pr.Issue.ID, fmt.Sprintf("mentions #%d", i2.Index))
	unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: i2.ID, RefIssueID: pr.Issue.ID, RefCommentID: c2.ID})

	// Must be superseded by c4/r4
	c3 := testCreateComment(t, 2, pr.Issue.ID, fmt.Sprintf("reopens #%d", i3.Index))
	unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: i3.ID, RefIssueID: pr.Issue.ID, RefCommentID: c3.ID})

	c4 := testCreateComment(t, 2, pr.Issue.ID, fmt.Sprintf("closes #%d", i3.Index))
	r4 := unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: i3.ID, RefIssueID: pr.Issue.ID, RefCommentID: c4.ID})

	refs, err := pr.ResolveCrossReferences(db.DefaultContext)
	assert.NoError(t, err)
	assert.Len(t, refs, 3)
	assert.Equal(t, rp.ID, refs[0].ID, "bad ref rp: %+v", refs[0])
	assert.Equal(t, r1.ID, refs[1].ID, "bad ref r1: %+v", refs[1])
	assert.Equal(t, r4.ID, refs[2].ID, "bad ref r4: %+v", refs[2])
}

func testCreateIssue(t *testing.T, repo, doer int64, title, content string, ispull bool) *issues_model.Issue {
	r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo})
	d := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: doer})

	ctx, committer, err := db.TxContext(db.DefaultContext)
	assert.NoError(t, err)
	defer committer.Close()

	idx, err := db.GetNextResourceIndex(ctx, "issue_index", r.ID)
	assert.NoError(t, err)
	i := &issues_model.Issue{
		RepoID:   r.ID,
		PosterID: d.ID,
		Poster:   d,
		Title:    title,
		Content:  content,
		IsPull:   ispull,
		Index:    idx,
	}

	err = issues_model.NewIssueWithIndex(ctx, d, issues_model.NewIssueOptions{
		Repo:  r,
		Issue: i,
	})
	assert.NoError(t, err)
	i, err = issues_model.GetIssueByID(ctx, i.ID)
	assert.NoError(t, err)
	assert.NoError(t, i.AddCrossReferences(ctx, d, false))
	assert.NoError(t, committer.Commit())
	return i
}

func testCreatePR(t *testing.T, repo, doer int64, title, content string) *issues_model.PullRequest {
	r := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo})
	d := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: doer})
	i := &issues_model.Issue{RepoID: r.ID, PosterID: d.ID, Poster: d, Title: title, Content: content, IsPull: true}
	pr := &issues_model.PullRequest{HeadRepoID: repo, BaseRepoID: repo, HeadBranch: "head", BaseBranch: "base", Status: issues_model.PullRequestStatusMergeable}
	assert.NoError(t, newPullRequest(db.DefaultContext, r, i, nil, nil, pr))
	pr.Issue = i
	return pr
}

func testCreateComment(t *testing.T, doer, issue int64, content string) *issues_model.Comment {
	d := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: doer})
	i := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: issue})
	c := &issues_model.Comment{Type: issues_model.CommentTypeComment, PosterID: doer, Poster: d, IssueID: issue, Issue: i, Content: content}

	ctx, committer, err := db.TxContext(db.DefaultContext)
	assert.NoError(t, err)
	defer committer.Close()
	err = db.Insert(ctx, c)
	assert.NoError(t, err)
	assert.NoError(t, c.AddCrossReferences(ctx, d, false))
	assert.NoError(t, committer.Commit())
	return c
}
