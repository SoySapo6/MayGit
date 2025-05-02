// Copyright 2020 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package misc

import (
	"errors"
	"fmt"

	asymkey_service "code.gitea.io/gitea/services/asymkey"
	"code.gitea.io/gitea/services/context"
)

// SigningKey returns the public key of the default signing key if it exists
func SigningKey(ctx *context.APIContext) {
	// swagger:operation GET /signing-key.gpg miscellaneous getSigningKey
	// ---
	// summary: Get default signing-key.gpg
	// produces:
	//     - text/plain
	// responses:
	//   "200":
	//     description: "GPG armored public key"
	//     schema:
	//       type: string

	// swagger:operation GET /repos/{owner}/{repo}/signing-key.gpg repository repoSigningKey
	// ---
	// summary: Get signing-key.gpg for given repository
	// produces:
	//     - text/plain
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     description: "GPG armored public key"
	//     schema:
	//       type: string

	path := ""
	if ctx.Repo != nil && ctx.Repo.Repository != nil {
		path = ctx.Repo.Repository.RepoPath()
	}

	content, format, err := asymkey_service.PublicSigningKey(ctx, path)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}
	if format == "ssh" {
		ctx.APIErrorNotFound(errors.New("SSH keys are used for signing, not GPG"))
		return
	}
	_, err = ctx.Write([]byte(content))
	if err != nil {
		ctx.APIErrorInternal(fmt.Errorf("Error writing key content %w", err))
	}
}

// SigningKey returns the public key of the default signing key if it exists
func SigningKeySSH(ctx *context.APIContext) {
	// swagger:operation GET /signing-key.pub miscellaneous getSigningKeySSH
	// ---
	// summary: Get default signing-key.pub
	// produces:
	//     - text/plain
	// responses:
	//   "200":
	//     description: "ssh public key"
	//     schema:
	//       type: string

	// swagger:operation GET /repos/{owner}/{repo}/signing-key.pub repository repoSigningKeySSH
	// ---
	// summary: Get signing-key.pub for given repository
	// produces:
	//     - text/plain
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// responses:
	//   "200":
	//     description: "ssh public key"
	//     schema:
	//       type: string

	path := ""
	if ctx.Repo != nil && ctx.Repo.Repository != nil {
		path = ctx.Repo.Repository.RepoPath()
	}

	content, format, err := asymkey_service.PublicSigningKey(ctx, path)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}
	if format != "ssh" {
		ctx.APIErrorNotFound(errors.New("GPG keys are used for signing, not SSH"))
		return
	}
	_, err = ctx.Write([]byte(content))
	if err != nil {
		ctx.APIErrorInternal(fmt.Errorf("Error writing key content %w", err))
	}
}
