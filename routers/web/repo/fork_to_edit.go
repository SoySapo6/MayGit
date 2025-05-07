// Copyright 2016 The Gogs Authors. All rights reserved.
// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"fmt"
	"net/http"
	"path"

	git_model "code.gitea.io/gitea/models/git"
	access_model "code.gitea.io/gitea/models/perm/access"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/unit"
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/log"
	repo_module "code.gitea.io/gitea/modules/repository"
	"code.gitea.io/gitea/modules/templates"
	"code.gitea.io/gitea/modules/util"
	"code.gitea.io/gitea/modules/web"
	"code.gitea.io/gitea/services/context"
	"code.gitea.io/gitea/services/forms"
	repo_service "code.gitea.io/gitea/services/repository"
)

const (
	tplForkFile templates.TplName = "repo/editor/fork"
)

// getEditRepository returns the repository where the actual edits will be written to.
// This may be a fork of the repository owned by the user. If no repository can be found
// for editing, nil is returned along with a message explaining why editing is not possible.
func getEditRepository(ctx *context.Context) (*repo_model.Repository, any, error) {
	if context.CanWriteToBranch(ctx, ctx.Doer, ctx.Repo.Repository, ctx.Repo.BranchName) {
		return ctx.Repo.Repository, nil, nil
	}

	// If we can't write to the branch, try find a user fork to create a branch in instead
	userRepo, err := repo_model.GetUserFork(ctx, ctx.Repo.Repository.ID, ctx.Doer.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("GetUserFork: %v", err)
	}
	if userRepo == nil {
		return nil, nil, nil
	}

	// Load repository information
	if err := userRepo.LoadOwner(ctx); err != nil {
		return nil, nil, fmt.Errorf("LoadOwner: v", err)
	}
	if err := userRepo.GetBaseRepo(ctx); err != nil || userRepo.BaseRepo == nil {
		if err != nil {
			return nil, nil, fmt.Errorf("GetBaseRepo: %v", err)
		}
		return nil, nil, fmt.Errorf("GetBaseRepo: Expected a base repo for user fork")
	}

	// Check code unit, archiving and permissions.
	if !userRepo.UnitEnabled(ctx, unit.TypeCode) {
		return nil, ctx.Tr("repo.editor.fork_code_disabled", userRepo.FullName()), nil
	}
	if userRepo.IsArchived {
		return nil, ctx.Tr("repo.editor.fork_is_archived", userRepo.FullName()), nil
	}
	permission, err := access_model.GetUserRepoPermission(ctx, userRepo, ctx.Doer)
	if err != nil {
		return nil, nil, fmt.Errorf("access_model.GetUserRepoPermission: %v", err)
	}
	if !permission.CanWrite(unit.TypeCode) {
		return nil, ctx.Tr("repo.editor.fork_no_permission", userRepo.FullName()), nil
	}

	return userRepo, nil, nil
}

// getEditRepositoryOrFork returns the repository where the edits will be written to.
// If no repository is editable, redirects to a page to create a fork.
func getEditRepositoryOrFork(ctx *context.Context, editOperation string) *repo_model.Repository {
	editRepo, notEditableMessage, err := getEditRepository(ctx)
	if err != nil {
		ctx.ServerError("getEditRepository", err)
		return nil
	}
	if editRepo == nil {
		// No editable repository, suggest to create a fork
		forkToEditFileCommon(ctx, editOperation, ctx.Repo.TreePath, notEditableMessage)
		ctx.HTML(http.StatusOK, tplForkFile)
		return nil
	}
	if editRepo.ID != ctx.Repo.Repository.ID {
		ctx.Data["ForkRepo"] = editRepo
	}
	return editRepo
}

// getEditRepositoryOrError returns the repository where the edits will be written to.
// If no repository is editable, display an error.
func getEditRepositoryOrError(ctx *context.Context, tpl templates.TplName, form any) *repo_model.Repository {
	editRepo, _, err := getEditRepository(ctx)
	if err != nil {
		ctx.ServerError("getEditRepository", err)
		return nil
	}
	if editRepo == nil {
		// No editable repo, maybe the fork was deleted in the meantime
		ctx.RenderWithErr(ctx.Tr("repo.editor.cannot_find_editable_repo"), tpl, form)
		return nil
	}
	if editRepo.ID != ctx.Repo.Repository.ID {
		ctx.Data["ForkRepo"] = editRepo
	}
	return editRepo
}

// CheckPushEditBranch chesk if pushing to the branch in the edit repository is possible,
// and if not renders an error and returns false.
func canPushToEditRepository(ctx *context.Context, editRepo *repo_model.Repository, branchName, commitChoice string, tpl templates.TplName, form any) bool {
	// When pushing to a fork or chosing to commit to a new branch, it should not exist yet
	if editRepo.ID != ctx.Repo.Repository.ID || commitChoice == frmCommitChoiceNewBranch {
		if exist, err := git_model.IsBranchExist(ctx, editRepo.ID, branchName); err == nil && exist {
			ctx.Data["Err_NewBranchName"] = true
			ctx.RenderWithErr(ctx.Tr("repo.editor.branch_already_exists", branchName), tpl, form)
			return false
		}
	}

	// Check for protected branch
	canCommitToBranch, err := context.CanCommitToBranch(ctx, ctx.Doer, editRepo, branchName)
	if err != nil {
		log.Error("CanCommitToBranch: %v", err)
	}
	if !canCommitToBranch.CanCommitToBranch {
		ctx.Data["Err_NewBranchName"] = true
		ctx.RenderWithErr(ctx.Tr("repo.editor.cannot_commit_to_protected_branch", branchName), tpl, form)
		return false
	}

	return true
}

// pushToEditRepositoryOrError pushes the branch that editing will be applied on top of
// to the user fork, if needed. On failure, it displays and returns an error. The
// branch name to be used for editing is returned.
func pushToEditRepositoryOrError(ctx *context.Context, editRepo *repo_model.Repository, branchName string, tpl templates.TplName, form any) (string, error) {
	// If editing the same repository, no need to push anything
	if editRepo.ID == ctx.Repo.Repository.ID {
		return ctx.Repo.BranchName, nil
	}

	// If editing a user fork, first push the branch to that repository
	baseRepo := ctx.Repo.Repository
	baseBranchName := ctx.Repo.BranchName

	log.Trace("pushBranchToUserRepo: pushing branch to user repo for editing: %s:%s %s:%s", baseRepo.FullName(), baseBranchName, editRepo.FullName(), branchName)

	if err := git.Push(ctx, baseRepo.RepoPath(), git.PushOptions{
		Remote: editRepo.RepoPath(),
		Branch: baseBranchName + ":" + branchName,
		Env:    repo_module.PushingEnvironment(ctx.Doer, editRepo),
	}); err != nil {
		ctx.RenderWithErr(ctx.Tr("repo.editor.fork_failed_to_push_branch", branchName), tpl, form)
		return "", err
	}

	return branchName, nil
}

// markRepositoryAsNonEmpty marks the repository as no longer empty
func markRepositoryAsNonEmpty(ctx *context.Context, editRepo *repo_model.Repository) {
	if !editRepo.IsEmpty {
		return
	}
	_ = repo_model.UpdateRepositoryCols(ctx, &repo_model.Repository{ID: editRepo.ID, IsEmpty: false}, "is_empty")
}

func forkToEditFileCommon(ctx *context.Context, editOperation, treePath string, notEditableMessage any) {
	treeNames, treePaths := getParentTreeFields(treePath)

	ctx.Data["EditOperation"] = editOperation
	ctx.Data["TreePath"] = treePath
	ctx.Data["TreeNames"] = treeNames
	ctx.Data["TreePaths"] = treePaths
	ctx.Data["CanForkRepo"] = notEditableMessage == nil
	ctx.Data["NotEditableMessage"] = notEditableMessage
}

func ForkToEditFilePost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.ForkToEditRepoFileForm)

	editRepo, notEditableMessage, err := getEditRepository(ctx)
	if err != nil {
		ctx.ServerError("getEditRepository", err)
		return
	}

	// Fork repository, if it doesn't already exist
	if editRepo == nil && notEditableMessage == nil {
		forkRepo := forkRepositoryOrError(ctx, ctx.Doer, repo_service.ForkRepoOptions{
			BaseRepo:     ctx.Repo.Repository,
			Name:         getUniqueRepositoryName(ctx, ctx.Repo.Repository.Name),
			Description:  ctx.Repo.Repository.Description,
			SingleBranch: ctx.Repo.BranchName,
		}, tplForkFile, form)
		if forkRepo == nil {
			forkToEditFileCommon(ctx, form.EditOperation, form.TreePath, notEditableMessage)
			ctx.HTML(http.StatusOK, tplForkFile)
			return
		}
	}

	// Redirect back to editing page
	ctx.Redirect(path.Join(ctx.Repo.RepoLink, form.EditOperation, util.PathEscapeSegments(ctx.Repo.BranchName), util.PathEscapeSegments(form.TreePath)))
}

// getUniqueRepositoryName Gets a unique repository name for a user
// It will append a -<num> postfix if the name is already taken
func getUniqueRepositoryName(ctx *context.Context, name string) string {
	uniqueName := name
	i := 1

	for {
		_, err := repo_model.GetRepositoryByName(ctx, ctx.Doer.ID, uniqueName)
		if err != nil || repo_model.IsErrRepoNotExist(err) {
			return uniqueName
		}

		uniqueName = fmt.Sprintf("%s-%d", name, i)
		i++
	}
}
