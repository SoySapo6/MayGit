// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2018 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package setting

import (
	"bytes"
	"encoding/base64"
	"html/template"
	"image/png"
	"net/http"
	"strings"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/web"
	"code.gitea.io/gitea/services/forms"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// RegenerateScratchTwoFactor regenerates the user's 2FA scratch code.
func RegenerateScratchTwoFactor(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("settings")
	ctx.Data["PageIsSettingsSecurity"] = true

	t, err := models.GetTwoFactorByUID(ctx.User.ID)
	if err != nil {
		if models.IsErrTwoFactorNotEnrolled(err) {
			ctx.Flash.Error(ctx.Tr("settings.twofa_not_enrolled"))
			ctx.Redirect(setting.AppSubURL + "/user/settings/security")
		}
		ctx.ServerError("SettingsTwoFactor: Failed to GetTwoFactorByUID", err)
		return
	}

	token, err := t.GenerateScratchToken()
	if err != nil {
		ctx.ServerError("SettingsTwoFactor: Failed to GenerateScratchToken", err)
		return
	}

	if err = models.UpdateTwoFactor(t); err != nil {
		ctx.ServerError("SettingsTwoFactor: Failed to UpdateTwoFactor", err)
		return
	}

	ctx.Flash.Success(ctx.Tr("settings.twofa_scratch_token_regenerated", token))
	ctx.Redirect(setting.AppSubURL + "/user/settings/security")
}

// DisableTwoFactor deletes the user's 2FA settings.
func DisableTwoFactor(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("settings")
	ctx.Data["PageIsSettingsSecurity"] = true

	t, err := models.GetTwoFactorByUID(ctx.User.ID)
	if err != nil {
		if models.IsErrTwoFactorNotEnrolled(err) {
			ctx.Flash.Error(ctx.Tr("settings.twofa_not_enrolled"))
			ctx.Redirect(setting.AppSubURL + "/user/settings/security")
		}
		ctx.ServerError("SettingsTwoFactor: Failed to GetTwoFactorByUID", err)
		return
	}

	if err = models.DeleteTwoFactorByID(t.ID, ctx.User.ID); err != nil {
		if models.IsErrTwoFactorNotEnrolled(err) {
			// There is a potential DB race here - we must have been disabled by another request in the intervening period
			ctx.Flash.Success(ctx.Tr("settings.twofa_disabled"))
			ctx.Redirect(setting.AppSubURL + "/user/settings/security")
		}
		ctx.ServerError("SettingsTwoFactor: Failed to DeleteTwoFactorByID", err)
		return
	}

	ctx.Flash.Success(ctx.Tr("settings.twofa_disabled"))
	ctx.Redirect(setting.AppSubURL + "/user/settings/security")
}

func twofaGenerateSecretAndQr(ctx *context.Context) bool {
	var otpKey *otp.Key
	var err error
	uri := ctx.Session.Get("twofaUri")
	if uri != nil {
		otpKey, err = otp.NewKeyFromURL(uri.(string))
		if err != nil {
			ctx.ServerError("SettingsTwoFactor: Failed NewKeyFromURL: ", err)
			return false
		}
	}
	// Filter unsafe character ':' in issuer
	issuer := strings.ReplaceAll(setting.AppName+" ("+setting.Domain+")", ":", "")
	if otpKey == nil {
		otpKey, err = totp.Generate(totp.GenerateOpts{
			SecretSize:  40,
			Issuer:      issuer,
			AccountName: ctx.User.Name,
		})
		if err != nil {
			ctx.ServerError("SettingsTwoFactor: totpGenerate Failed", err)
			return false
		}
	}

	ctx.Data["TwofaSecret"] = otpKey.Secret()
	img, err := otpKey.Image(320, 240)
	if err != nil {
		ctx.ServerError("SettingsTwoFactor: otpKey image generation failed", err)
		return false
	}

	var imgBytes bytes.Buffer
	if err = png.Encode(&imgBytes, img); err != nil {
		ctx.ServerError("SettingsTwoFactor: otpKey png encoding failed", err)
		return false
	}

	ctx.Data["QrUri"] = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(imgBytes.Bytes()))

	if err := ctx.Session.Set("twofaSecret", otpKey.Secret()); err != nil {
		ctx.ServerError("SettingsTwoFactor: Failed to set session for twofaSecret", err)
		return false
	}

	if err := ctx.Session.Set("twofaUri", otpKey.String()); err != nil {
		ctx.ServerError("SettingsTwoFactor: Failed to set session for twofaUri", err)
		return false
	}

	// Here we're just going to try to release the session early
	if err := ctx.Session.Release(); err != nil {
		// we'll tolerate errors here as they *should* get saved elsewhere
		log.Error("Unable to save changes to the session: %v", err)
	}
	return true
}

// EnrollTwoFactor shows the page where the user can enroll into 2FA.
func EnrollTwoFactor(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("settings")
	ctx.Data["PageIsSettingsSecurity"] = true

	t, err := models.GetTwoFactorByUID(ctx.User.ID)
	if t != nil {
		// already enrolled - we should redirect back!
		log.Warn("Trying to re-enroll %-v in twofa when already enrolled", ctx.User)
		ctx.Flash.Error(ctx.Tr("settings.twofa_is_enrolled"))
		ctx.Redirect(setting.AppSubURL + "/user/settings/security")
		return
	}
	if err != nil && !models.IsErrTwoFactorNotEnrolled(err) {
		ctx.ServerError("SettingsTwoFactor: GetTwoFactorByUID", err)
		return
	}

	if !twofaGenerateSecretAndQr(ctx) {
		return
	}

	ctx.HTML(http.StatusOK, tplSettingsTwofaEnroll)
}

// EnrollTwoFactorPost handles enrolling the user into 2FA.
func EnrollTwoFactorPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.TwoFactorAuthForm)
	ctx.Data["Title"] = ctx.Tr("settings")
	ctx.Data["PageIsSettingsSecurity"] = true

	t, err := models.GetTwoFactorByUID(ctx.User.ID)
	if t != nil {
		// already enrolled
		ctx.Flash.Error(ctx.Tr("settings.twofa_is_enrolled"))
		ctx.Redirect(setting.AppSubURL + "/user/settings/security")
		return
	}
	if err != nil && !models.IsErrTwoFactorNotEnrolled(err) {
		ctx.ServerError("SettingsTwoFactor: Failed to check if already enrolled with GetTwoFactorByUID", err)
		return
	}

	if ctx.HasError() {
		if !twofaGenerateSecretAndQr(ctx) {
			return
		}
		ctx.HTML(http.StatusOK, tplSettingsTwofaEnroll)
		return
	}

	secretRaw := ctx.Session.Get("twofaSecret")
	if secretRaw == nil {
		ctx.Flash.Error(ctx.Tr("settings.twofa_failed_get_secret"))
		ctx.Redirect(setting.AppSubURL + "/user/settings/security/two_factor/enroll")
		return
	}

	secret := secretRaw.(string)
	if !totp.Validate(form.Passcode, secret) {
		if !twofaGenerateSecretAndQr(ctx) {
			return
		}
		ctx.Flash.Error(ctx.Tr("settings.passcode_invalid"))
		ctx.Redirect(setting.AppSubURL + "/user/settings/security/two_factor/enroll")
		return
	}

	t = &models.TwoFactor{
		UID: ctx.User.ID,
	}
	err = t.SetSecret(secret)
	if err != nil {
		ctx.ServerError("SettingsTwoFactor: Failed to set secret", err)
		return
	}
	token, err := t.GenerateScratchToken()
	if err != nil {
		ctx.ServerError("SettingsTwoFactor: Failed to generate scratch token", err)
		return
	}

	// Now we have to delete the secrets - because if we fail to insert then it's highly likely that they have already been used
	// If we can detect the unique constraint failure below we can move this to after the NewTwoFactor
	if err := ctx.Session.Delete("twofaSecret"); err != nil {
		// tolerate this failure - it's more important to continue
		log.Error("Unable to delete twofaSecret from the session: Error: %v", err)
	}
	if err := ctx.Session.Delete("twofaUri"); err != nil {
		// tolerate this failure - it's more important to continue
		log.Error("Unable to delete twofaUri from the session: Error: %v", err)
	}
	if err := ctx.Session.Release(); err != nil {
		// tolerate this failure - it's more important to continue
		log.Error("Unable to save changes to the session: %v", err)
	}

	if err = models.NewTwoFactor(t); err != nil {
		// FIXME: We need to handle a unique constraint fail here it's entirely possible that another request has beaten us.
		// If there is a unique constraint fail we should just tolerate the error
		ctx.ServerError("SettingsTwoFactor: Failed to save two factor", err)
		return
	}

	ctx.Flash.Success(ctx.Tr("settings.twofa_enrolled", token))
	ctx.Redirect(setting.AppSubURL + "/user/settings/security")
}
