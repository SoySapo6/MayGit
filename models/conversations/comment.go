// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package conversations

// This comment.go was refactored from issues/comment.go to make it context-agnostic to improve reusability.

import (
	"context"
	"fmt"
	"html/template"

	"code.gitea.io/gitea/models/db"
	repo_model "code.gitea.io/gitea/models/repo"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/container"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/structs"
	"code.gitea.io/gitea/modules/timeutil"
	"code.gitea.io/gitea/modules/translation"
	"code.gitea.io/gitea/modules/util"

	"xorm.io/builder"
)

// ErrCommentNotExist represents a "CommentNotExist" kind of error.
type ErrCommentNotExist struct {
	ID             int64
	ConversationID int64
}

// IsErrCommentNotExist checks if an error is a ErrCommentNotExist.
func IsErrCommentNotExist(err error) bool {
	_, ok := err.(ErrCommentNotExist)
	return ok
}

func (err ErrCommentNotExist) Error() string {
	return fmt.Sprintf("comment does not exist [id: %d, conversation_id: %d]", err.ID, err.ConversationID)
}

func (err ErrCommentNotExist) Unwrap() error {
	return util.ErrNotExist
}

var ErrCommentAlreadyChanged = util.NewInvalidArgumentErrorf("the comment is already changed")

// CommentType defines whether a comment is just a simple comment, an action (like close) or a reference.
type CommentType int

// CommentTypeUndefined is used to search for comments of any type
const CommentTypeUndefined CommentType = -1

const (
	CommentTypeComment CommentType = iota // 0 Plain comment, can be associated with a commit (CommitID > 0) and a line (LineNum > 0)

	CommentTypeLock   // 1 Lock an conversation, giving only collaborators access
	CommentTypeUnlock // 2 Unlocks a previously locked conversation

	CommentTypeAddDependency
	CommentTypeRemoveDependency
)

var commentStrings = []string{
	"comment",
	"lock",
	"unlock",
}

func (t CommentType) String() string {
	return commentStrings[t]
}

func AsCommentType(typeName string) CommentType {
	for index, name := range commentStrings {
		if typeName == name {
			return CommentType(index)
		}
	}
	return CommentTypeUndefined
}

func (t CommentType) HasContentSupport() bool {
	switch t {
	case CommentTypeComment:
		return true
	}
	return false
}

func (t CommentType) HasAttachmentSupport() bool {
	switch t {
	case CommentTypeComment:
		return true
	}
	return false
}

func (t CommentType) HasMailReplySupport() bool {
	switch t {
	case CommentTypeComment:
		return true
	}
	return false
}

// ConversationComment represents a comment in commit and conversation page.
// ConversationComment struct should not contain any pointers unrelated to Conversation unless absolutely necessary.
// To have pointers outside of conversation, create another comment type (e.g. ConversationComment) and use a converter to load it in.
// The database data for the comments however, for all comment types, are defined here.
type ConversationComment struct {
	ID   int64       `xorm:"pk autoincr"`
	Type CommentType `xorm:"INDEX"`

	PosterID int64            `xorm:"INDEX"`
	Poster   *user_model.User `xorm:"-"`

	OriginalAuthor   string
	OriginalAuthorID int64 `xorm:"INDEX"`

	Attachments []*repo_model.Attachment `xorm:"-"`
	Reactions   ReactionList             `xorm:"-"`

	Content        string `xorm:"LONGTEXT"`
	ContentVersion int    `xorm:"NOT NULL DEFAULT 0"`

	ConversationID int64         `xorm:"INDEX"`
	Conversation   *Conversation `xorm:"-"`

	CreatedUnix timeutil.TimeStamp `xorm:"INDEX created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"INDEX updated"`

	RenderedContent template.HTML  `xorm:"-"`
	ShowRole        RoleDescriptor `xorm:"-"`
}

func init() {
	db.RegisterModel(new(ConversationComment))
}

// LoadPoster loads comment poster
func (c *ConversationComment) LoadPoster(ctx context.Context) (err error) {
	if c.Poster != nil {
		return nil
	}

	c.Poster, err = user_model.GetPossibleUserByID(ctx, c.PosterID)
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			c.PosterID = user_model.GhostUserID
			c.Poster = user_model.NewGhostUser()
		} else {
			log.Error("getUserByID[%d]: %v", c.ID, err)
		}
	}
	return err
}

// LoadReactions loads comment reactions
func (c *ConversationComment) LoadReactions(ctx context.Context, repo *repo_model.Repository) (err error) {
	if c.Reactions != nil {
		return nil
	}
	c.Reactions, _, err = FindReactions(ctx, FindReactionsOptions{
		ConversationID: c.ConversationID,
		CommentID:      c.ID,
	})
	if err != nil {
		return err
	}
	// Load reaction user data
	if _, err := c.Reactions.LoadUsers(ctx, repo); err != nil {
		return err
	}
	return nil
}

// AfterDelete is invoked from XORM after the object is deleted.
func (c *ConversationComment) AfterDelete(ctx context.Context) {
	if c.ID <= 0 {
		return
	}

	_, err := repo_model.DeleteAttachmentsByComment(ctx, c.ID, true)
	if err != nil {
		log.Info("Could not delete files for comment %d on conversation #%d: %s", c.ID, c.ConversationID, err)
	}
}

// RoleInRepo presents the user's participation in the repo
type RoleInRepo string

// RoleDescriptor defines comment "role" tags
type RoleDescriptor struct {
	IsPoster   bool
	RoleInRepo RoleInRepo
}

// Enumerate all the role tags.
const (
	RoleRepoOwner                RoleInRepo = "owner"
	RoleRepoMember               RoleInRepo = "member"
	RoleRepoCollaborator         RoleInRepo = "collaborator"
	RoleRepoFirstTimeContributor RoleInRepo = "first_time_contributor"
	RoleRepoContributor          RoleInRepo = "contributor"
)

// LocaleString returns the locale string name of the role
func (r RoleInRepo) LocaleString(lang translation.Locale) string {
	return lang.TrString("repo.conversations.role." + string(r))
}

// LocaleHelper returns the locale tooltip of the role
func (r RoleInRepo) LocaleHelper(lang translation.Locale) string {
	return lang.TrString("repo.conversations.role." + string(r) + "_helper")
}

// CreateCommentOptions defines options for creating comment
type CreateCommentOptions struct {
	Type                    CommentType
	Doer                    *user_model.User
	Repo                    *repo_model.Repository
	Attachments             []string // UUIDs of attachments
	ConversationID          int64
	Conversation            *Conversation
	Content                 string
	DependentConversationID int64
}

// CreateComment creates comment with context
func CreateComment(ctx context.Context, opts *CreateCommentOptions) (_ *ConversationComment, err error) {
	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return nil, err
	}
	defer committer.Close()

	e := db.GetEngine(ctx)

	comment := &ConversationComment{
		Type:           opts.Type,
		PosterID:       opts.Doer.ID,
		Poster:         opts.Doer,
		Content:        opts.Content,
		Conversation:   opts.Conversation,
		ConversationID: opts.Conversation.ID,
	}
	if _, err = e.Insert(comment); err != nil {
		return nil, err
	}

	if err = opts.Repo.LoadOwner(ctx); err != nil {
		return nil, err
	}

	if err = updateCommentInfos(ctx, opts); err != nil {
		return nil, err
	}

	if err = committer.Commit(); err != nil {
		return nil, err
	}
	return comment, nil
}

// GetCommentByID returns the comment by given ID.
func GetCommentByID(ctx context.Context, id int64) (*ConversationComment, error) {
	c := new(ConversationComment)
	has, err := db.GetEngine(ctx).ID(id).Get(c)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrCommentNotExist{id, 0}
	}
	return c, nil
}

// FindCommentsOptions describes the conditions to Find comments
type FindCommentsOptions struct {
	db.ListOptions
	RepoID          int64
	ConversationID  int64
	Since           int64
	Before          int64
	Type            CommentType
	ConversationIDs []int64
}

// ToConds implements FindOptions interface
func (opts FindCommentsOptions) ToConds() builder.Cond {
	cond := builder.NewCond()
	if opts.RepoID > 0 {
		cond = cond.And(builder.Eq{"conversation.repo_id": opts.RepoID})
	}
	if opts.ConversationID > 0 {
		cond = cond.And(builder.Eq{"conversation_comment.conversation_id": opts.ConversationID})
	} else if len(opts.ConversationIDs) > 0 {
		cond = cond.And(builder.In("conversation_comment.conversation_id", opts.ConversationIDs))
	}
	if opts.Since > 0 {
		cond = cond.And(builder.Gte{"conversation_comment.updated_unix": opts.Since})
	}
	if opts.Before > 0 {
		cond = cond.And(builder.Lte{"conversation_comment.updated_unix": opts.Before})
	}
	if opts.Type != CommentTypeUndefined {
		cond = cond.And(builder.Eq{"conversation_comment.type": opts.Type})
	}
	return cond
}

// FindComments returns all comments according options
func FindComments(ctx context.Context, opts *FindCommentsOptions) (CommentList, error) {
	comments := make([]*ConversationComment, 0, 10)
	sess := db.GetEngine(ctx).Where(opts.ToConds())
	if opts.RepoID > 0 {
		sess.Join("INNER", "conversation", "conversation.id = conversation_comment.conversation_id")
	}

	if opts.Page != 0 {
		sess = db.SetSessionPagination(sess, opts)
	}

	// WARNING: If you change this order you will need to fix createCodeComment

	return comments, sess.
		Asc("conversation_comment.created_unix").
		Asc("conversation_comment.id").
		Find(&comments)
}

// CountComments count all comments according options by ignoring pagination
func CountComments(ctx context.Context, opts *FindCommentsOptions) (int64, error) {
	sess := db.GetEngine(ctx).Where(opts.ToConds())
	if opts.RepoID > 0 {
		sess.Join("INNER", "conversation", "conversation.id = conversation_comment.conversation_id")
	}
	return sess.Count(&ConversationComment{})
}

// UpdateCommentInvalidate updates comment invalidated column
func UpdateCommentInvalidate(ctx context.Context, c *ConversationComment) error {
	_, err := db.GetEngine(ctx).ID(c.ID).Cols("invalidated").Update(c)
	return err
}

// UpdateComment updates information of comment
func UpdateComment(ctx context.Context, c *ConversationComment, contentVersion int, doer *user_model.User) error {
	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()
	sess := db.GetEngine(ctx)

	c.ContentVersion = contentVersion + 1

	affected, err := sess.ID(c.ID).AllCols().Where("content_version = ?", contentVersion).Update(c)
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrCommentAlreadyChanged
	}
	if err := committer.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil
}

// DeleteComment deletes the comment
func DeleteComment(ctx context.Context, comment *ConversationComment) error {
	e := db.GetEngine(ctx)
	if _, err := e.ID(comment.ID).NoAutoCondition().Delete(comment); err != nil {
		return err
	}

	if _, err := db.DeleteByBean(ctx, &ConversationContentHistory{
		CommentID: comment.ID,
	}); err != nil {
		return err
	}

	if comment.Type == CommentTypeComment {
		if _, err := e.ID(comment.ConversationID).Decr("num_comments").Update(new(Conversation)); err != nil {
			return err
		}
	}

	if _, err := e.Table("action").
		Where("comment_id = ?", comment.ID).
		Update(map[string]any{
			"is_deleted": true,
		}); err != nil {
		return err
	}

	return DeleteReaction(ctx, &ReactionOptions{CommentID: comment.ID})
}

// UpdateCommentsMigrationsByType updates comments' migrations information via given git service type and original id and poster id
func UpdateCommentsMigrationsByType(ctx context.Context, tp structs.GitServiceType, originalAuthorID string, posterID int64) error {
	_, err := db.GetEngine(ctx).Table("conversation_comment").
		Join("INNER", "conversation", "conversation.id = conversation_comment.conversation_id").
		Join("INNER", "repository", "conversation.repo_id = repository.id").
		Where("repository.original_service_type = ?", tp).
		And("conversation_comment.original_author_id = ?", originalAuthorID).
		Update(map[string]any{
			"poster_id":          posterID,
			"original_author":    "",
			"original_author_id": 0,
		})
	return err
}

func UpdateAttachments(ctx context.Context, opts *CreateCommentOptions, comment *ConversationComment) error {
	attachments, err := repo_model.GetAttachmentsByUUIDs(ctx, opts.Attachments)
	if err != nil {
		return fmt.Errorf("getAttachmentsByUUIDs [uuids: %v]: %w", opts.Attachments, err)
	}
	for i := range attachments {
		attachments[i].ConversationID = comment.ConversationID
		attachments[i].CommentID = comment.ID
		// No assign value could be 0, so ignore AllCols().
		if _, err = db.GetEngine(ctx).ID(attachments[i].ID).Update(attachments[i]); err != nil {
			return fmt.Errorf("update attachment [%d]: %w", attachments[i].ID, err)
		}
	}
	comment.Attachments = attachments
	return nil
}

// LoadConversation loads the conversation reference for the comment
func (c *ConversationComment) LoadConversation(ctx context.Context) (err error) {
	if c.Conversation != nil {
		return nil
	}
	c.Conversation, err = GetConversationByID(ctx, c.ConversationID)
	return err
}

// LoadAttachments loads attachments (it never returns error, the error during `GetAttachmentsByCommentIDCtx` is ignored)
func (c *ConversationComment) LoadAttachments(ctx context.Context) error {
	if len(c.Attachments) > 0 {
		return nil
	}

	var err error
	c.Attachments, err = repo_model.GetAttachmentsByCommentID(ctx, c.ID)
	if err != nil {
		log.Error("getAttachmentsByCommentID[%d]: %v", c.ID, err)
	}
	return nil
}

// UpdateAttachments update attachments by UUIDs for the comment
func (c *ConversationComment) UpdateAttachments(ctx context.Context, uuids []string) error {
	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	attachments, err := repo_model.GetAttachmentsByUUIDs(ctx, uuids)
	if err != nil {
		return fmt.Errorf("getAttachmentsByUUIDs [uuids: %v]: %w", uuids, err)
	}
	for i := 0; i < len(attachments); i++ {
		attachments[i].ConversationID = c.ConversationID
		attachments[i].CommentID = c.ID
		if err := repo_model.UpdateAttachment(ctx, attachments[i]); err != nil {
			return fmt.Errorf("update attachment [id: %d]: %w", attachments[i].ID, err)
		}
	}
	return committer.Commit()
}

// HashTag returns unique hash tag for conversation.
func (c *ConversationComment) HashTag() string {
	return fmt.Sprintf("comment-%d", c.ID)
}

func (c *ConversationComment) hashLink() string {
	return "#" + c.HashTag()
}

// HTMLURL formats a URL-string to the conversation-comment
func (c *ConversationComment) HTMLURL(ctx context.Context) string {
	err := c.LoadConversation(ctx)
	if err != nil { // Silently dropping errors :unamused:
		log.Error("LoadConversation(%d): %v", c.ConversationID, err)
		return ""
	}
	err = c.Conversation.LoadRepo(ctx)
	if err != nil { // Silently dropping errors :unamused:
		log.Error("loadRepo(%d): %v", c.Conversation.RepoID, err)
		return ""
	}
	return c.Conversation.HTMLURL() + c.hashLink()
}

// APIURL formats a API-string to the conversation-comment
func (c *ConversationComment) APIURL(ctx context.Context) string {
	err := c.LoadConversation(ctx)
	if err != nil { // Silently dropping errors :unamused:
		log.Error("LoadConversation(%d): %v", c.ConversationID, err)
		return ""
	}
	err = c.Conversation.LoadRepo(ctx)
	if err != nil { // Silently dropping errors :unamused:
		log.Error("loadRepo(%d): %v", c.Conversation.RepoID, err)
		return ""
	}

	return fmt.Sprintf("%s/conversations/comments/%d", c.Conversation.Repo.APIURL(), c.ID)
}

// HasOriginalAuthor returns if a comment was migrated and has an original author.
func (c *ConversationComment) HasOriginalAuthor() bool {
	return c.OriginalAuthor != "" && c.OriginalAuthorID != 0
}

func (c *ConversationComment) ConversationURL(ctx context.Context) string {
	err := c.LoadConversation(ctx)
	if err != nil { // Silently dropping errors :unamused:
		log.Error("LoadConversation(%d): %v", c.ConversationID, err)
		return ""
	}

	err = c.Conversation.LoadRepo(ctx)
	if err != nil { // Silently dropping errors :unamused:
		log.Error("loadRepo(%d): %v", c.Conversation.RepoID, err)
		return ""
	}
	return c.Conversation.HTMLURL()
}

// InsertConversationComments inserts many comments of conversations.
func InsertConversationComments(ctx context.Context, comments []*ConversationComment) error {
	if len(comments) == 0 {
		return nil
	}

	conversationIDs := container.FilterSlice(comments, func(comment *ConversationComment) (int64, bool) {
		return comment.ConversationID, true
	})

	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()
	for _, comment := range comments {
		if _, err := db.GetEngine(ctx).NoAutoTime().Insert(comment); err != nil {
			return err
		}

		for _, reaction := range comment.Reactions {
			reaction.ConversationID = comment.ConversationID
			reaction.CommentID = comment.ID
		}
		if len(comment.Reactions) > 0 {
			if err := db.Insert(ctx, comment.Reactions); err != nil {
				return err
			}
		}
	}

	for _, conversationID := range conversationIDs {
		if _, err := db.Exec(ctx, "UPDATE conversation set num_comments = (SELECT count(*) FROM conversation_comment WHERE conversation_id = ? AND `type`=?) WHERE id = ?",
			conversationID, CommentTypeComment, conversationID); err != nil {
			return err
		}
	}
	return committer.Commit()
}

func updateCommentInfos(ctx context.Context, opts *CreateCommentOptions) (err error) {
	// Check comment type.
	switch opts.Type {
	case CommentTypeComment:
		if _, err = db.Exec(ctx, "UPDATE `conversation` SET num_comments=num_comments+1 WHERE id=?", opts.Conversation.ID); err != nil {
			return err
		}
	}
	// update the conversation's updated_unix column
	return UpdateConversationCols(ctx, opts.Conversation, "updated_unix")
}
