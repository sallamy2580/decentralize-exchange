/*---------------------------------------------------------------------------------------------
 *  Copyright (c) IBAX. All rights reserved.
 *  See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/IBAX-io/go-ibax/packages/common/crypto"
	"github.com/IBAX-io/go-ibax/packages/conf"
	"github.com/IBAX-io/go-ibax/packages/conf/syspar"
	"github.com/IBAX-io/go-ibax/packages/consts"
	"github.com/IBAX-io/go-ibax/packages/converter"
	"github.com/IBAX-io/go-ibax/packages/publisher"
	"github.com/IBAX-io/go-ibax/packages/smart"
	"github.com/IBAX-io/go-ibax/packages/storage/sqldb"
	"github.com/IBAX-io/go-ibax/packages/transaction"
	"github.com/IBAX-io/go-ibax/packages/types"
	"github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"
)

// Special word used by frontend to sign UID generated by /getuid API command, sign is performed for contcatenated word and UID
func nonceSalt() string {
	return fmt.Sprintf("LOGIN%d", conf.Config.LocalConf.NetworkID)
}

type loginForm struct {
	EcosystemID int64          `schema:"ecosystem"`
	Expire      int64          `schema:"expire"`
	PublicKey   publicKeyValue `schema:"pubkey"`
	KeyID       string         `schema:"key_id"`
	Signature   hexValue       `schema:"signature"`
	RoleID      int64          `schema:"role_id"`
	IsMobile    bool           `schema:"mobile"`
}

type publicKeyValue struct {
	hexValue
}

func (pk *publicKeyValue) UnmarshalText(v []byte) (err error) {
	pk.value, err = hex.DecodeString(string(v))
	pk.value = crypto.CutPub(pk.value)
	return
}

func (f *loginForm) Validate(r *http.Request) error {
	if f.Expire == 0 {
		f.Expire = int64(jwtExpire)
	}

	return nil
}

type loginResult struct {
	Token       string        `json:"token,omitempty"`
	EcosystemID string        `json:"ecosystem_id,omitempty"`
	KeyID       string        `json:"key_id,omitempty"`
	Account     string        `json:"account,omitempty"`
	NotifyKey   string        `json:"notify_key,omitempty"`
	IsNode      bool          `json:"isnode,omitempty"`
	IsOwner     bool          `json:"isowner,omitempty"`
	IsCLB       bool          `json:"clb,omitempty"`
	Timestamp   string        `json:"timestamp,omitempty"`
	Roles       []rolesResult `json:"roles,omitempty"`
}

type rolesResult struct {
	RoleID   int64  `json:"role_id"`
	RoleName string `json:"role_name"`
}

func (m Mode) loginHandler(w http.ResponseWriter, r *http.Request) {
	var (
		publicKey           []byte
		wallet, founder, fm int64
		uid                 string
		err                 error
		isExistPub          bool
		form                = new(loginForm)
		spfounder, spfm     sqldb.StateParameter
	)
	if uid, err = getUID(r); err != nil {
		errorResponse(w, err, http.StatusBadRequest)
		return
	}

	if err = parseForm(r, form); err != nil {
		errorResponse(w, err, http.StatusBadRequest)
		return
	}

	client := getClient(r)
	logger := getLogger(r)

	if form.EcosystemID > 0 {
		client.EcosystemID = form.EcosystemID
	} else if client.EcosystemID == 0 {
		logger.WithFields(log.Fields{"type": consts.EmptyObject}).Warning("state is empty, using 1 as a state")
		client.EcosystemID = 1
	}

	if len(form.KeyID) > 0 {
		wallet = converter.StringToAddress(form.KeyID)
	} else if len(form.PublicKey.Bytes()) > 0 {
		wallet = crypto.Address(form.PublicKey.Bytes())
	}

	account := &sqldb.Key{}
	account.SetTablePrefix(client.EcosystemID)
	isAccount, err := account.Get(nil, wallet)
	if err != nil {
		logger.WithFields(log.Fields{"type": consts.DBError, "error": err}).Error("selecting public key from keys")
		errorResponse(w, err)
		return
	}

	spfm.SetTablePrefix(converter.Int64ToStr(client.EcosystemID))
	if ok, err := spfm.Get(nil, "free_membership"); err != nil {
		logger.WithFields(log.Fields{"type": consts.DBError, "error": err}).Error("getting free_membership parameter")
		errorResponse(w, err)
		return
	} else if ok {
		fm = converter.StrToInt64(spfm.Value)
	}
	publicKey = account.PublicKey
	isExistPub = len(publicKey) == 0

	isCan := func(a, e bool) bool {
		return !a || (a && e)
	}
	if isCan(isAccount, isExistPub) {
		if !(fm == 1 || client.EcosystemID == 1) {
			errorResponse(w, errEcoNotOpen.Errorf(client.EcosystemID))
			return
		}
	}

	if isAccount && !isExistPub {
		if account.Deleted == 1 {
			errorResponse(w, errDeletedKey)
			return
		}
	} else {
		if !allowCreateUser(client) {
			errorResponse(w, errKeyNotFound)
			return
		}
		if isCan(isAccount, isExistPub) {

			publicKey = form.PublicKey.Bytes()
			if len(publicKey) == 0 {
				logger.WithFields(log.Fields{"type": consts.EmptyObject}).Error("public key is empty")
				errorResponse(w, errEmptyPublic)
				return
			}

			nodePrivateKey := syspar.GetNodePrivKey()

			contract := smart.GetContract("NewUser", 1)
			sc := types.SmartTransaction{
				Header: &types.Header{
					ID:          int(contract.Info().ID),
					EcosystemID: 1,
					KeyID:       conf.Config.KeyID,
					NetworkID:   conf.Config.LocalConf.NetworkID,
				},
				Params: map[string]interface{}{
					"NewPubkey": hex.EncodeToString(publicKey),
					"Ecosystem": client.EcosystemID,
				},
			}

			stp := new(transaction.SmartTransactionParser)
			txData, err := stp.BinMarshal(&sc, nodePrivateKey, true)
			if err != nil {
				log.WithFields(log.Fields{"type": consts.ContractError, "err": err}).Error("Building transaction")
				errorResponse(w, err)
				return
			}

			if err := m.ContractRunner.RunContract(txData, stp.Hash, sc.KeyID, stp.Timestamp, logger); err != nil {
				errorResponse(w, err)
				return
			}

			if !conf.Config.IsSupportingCLB() {
				gt := 3 * syspar.GetMaxBlockGenerationTime()
				his := &sqldb.History{}
				for i := 0; i < 2; i++ {
					found, err := his.Get(stp.Hash)
					if err != nil {
						errorResponse(w, err)
						return
					}
					if found && his.BlockID > 0 {
						if strings.Contains(his.Comment, "(error)") {
							errorResponse(w, errors.New(`encountered some problems when login account`))
							return
						} else {
							_, _ = account.Get(nil, wallet)
							break
						}
					}
					time.Sleep(time.Duration(gt) * time.Millisecond)
				}

				if his.BlockID == 0 {
					errorResponse(w, errNewUser)
					return
				}
			}

		} else {
			logger.WithFields(log.Fields{"type": consts.EmptyObject}).Error("public key is empty, and state is not default")
			errorResponse(w, errStateLogin.Errorf(wallet, client.EcosystemID))
			return
		}
	}

	if len(publicKey) == 0 {
		if client.EcosystemID > 1 {
			logger.WithFields(log.Fields{"type": consts.EmptyObject}).Error("public key is empty, and state is not default")
			errorResponse(w, errStateLogin.Errorf(wallet, client.EcosystemID))
			return
		}

		if len(form.PublicKey.Bytes()) == 0 {
			logger.WithFields(log.Fields{"type": consts.EmptyObject}).Error("public key is empty")
			errorResponse(w, errEmptyPublic)
			return
		}
	}

	if form.RoleID != 0 && client.RoleID == 0 {
		checkedRole, err := checkRoleFromParam(form.RoleID, client.EcosystemID, account.AccountID)
		if err != nil {
			errorResponse(w, err)
			return
		}

		if checkedRole != form.RoleID {
			errorResponse(w, errCheckRole)
			return
		}

		client.RoleID = checkedRole
	}

	verify, err := crypto.CheckSign(publicKey, []byte(nonceSalt()+uid), form.Signature.Bytes())
	if err != nil {
		logger.WithFields(log.Fields{"type": consts.CryptoError, "pubkey": publicKey, "uid": uid, "signature": form.Signature.Bytes()}).Error("checking signature")
		errorResponse(w, err)
		return
	}

	if !verify {
		logger.WithFields(log.Fields{"type": consts.InvalidObject, "pubkey": publicKey, "uid": uid, "signature": form.Signature.Bytes()}).Error("incorrect signature")
		errorResponse(w, errSignature)
		return
	}

	spfounder.SetTablePrefix(converter.Int64ToStr(client.EcosystemID))
	if ok, err := spfounder.Get(nil, "founder_account"); err != nil {
		logger.WithFields(log.Fields{"type": consts.DBError, "error": err}).Error("getting founder_account parameter")
		errorResponse(w, err)
		return
	} else if ok {
		founder = converter.StrToInt64(spfounder.Value)
	}

	result := &loginResult{
		Account:     account.AccountID,
		EcosystemID: converter.Int64ToStr(client.EcosystemID),
		KeyID:       converter.Int64ToStr(wallet),
		IsOwner:     founder == wallet,
		IsNode:      conf.Config.KeyID == wallet,
		IsCLB:       conf.Config.IsSupportingCLB(),
	}

	claims := JWTClaims{
		KeyID:       result.KeyID,
		AccountID:   account.AccountID,
		EcosystemID: result.EcosystemID,
		IsMobile:    form.IsMobile,
		RoleID:      converter.Int64ToStr(form.RoleID),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(time.Second * time.Duration(form.Expire))},
		},
	}

	result.Token, err = generateJWTToken(claims)
	if err != nil {
		logger.WithFields(log.Fields{"type": consts.JWTError, "error": err}).Error("generating jwt token")
		errorResponse(w, err)
		return
	}

	result.NotifyKey, result.Timestamp, err = publisher.GetJWTCent(wallet, form.Expire)
	if err != nil {
		errorResponse(w, err)
		return
	}

	ra := &sqldb.RolesParticipants{}
	roles, err := ra.SetTablePrefix(client.EcosystemID).GetActiveMemberRoles(account.AccountID)
	if err != nil {
		logger.WithFields(log.Fields{"type": consts.DBError, "error": err}).Error("getting roles")
		errorResponse(w, err)
		return
	}

	for _, r := range roles {
		var res map[string]string
		if err := json.Unmarshal([]byte(r.Role), &res); err != nil {
			log.WithFields(log.Fields{"type": consts.JSONUnmarshallError, "error": err}).Error("unmarshalling role")
			errorResponse(w, err)
			return
		}

		result.Roles = append(result.Roles, rolesResult{
			RoleID:   converter.StrToInt64(res["id"]),
			RoleName: res["name"],
		})
	}

	jsonResponse(w, result)
}

func getUID(r *http.Request) (string, error) {
	var uid string

	token := getToken(r)
	if token != nil {
		if claims, ok := token.Claims.(*JWTClaims); ok {
			uid = claims.UID
		}
	} else if len(uid) == 0 {
		logger := getLogger(r)
		logger.WithFields(log.Fields{"type": consts.EmptyObject}).Warning("UID is empty")
		return "", errUnknownUID
	}

	return uid, nil
}

func checkRoleFromParam(role, ecosystemID int64, account string) (int64, error) {
	if role > 0 {
		ok, err := sqldb.MemberHasRole(nil, role, ecosystemID, account)
		if err != nil {
			log.WithFields(log.Fields{
				"type":      consts.DBError,
				"account":   account,
				"role":      role,
				"ecosystem": ecosystemID}).Error("check role")

			return 0, err
		}

		if !ok {
			log.WithFields(log.Fields{
				"type":      consts.NotFound,
				"account":   account,
				"role":      role,
				"ecosystem": ecosystemID,
			}).Error("member hasn't role")

			return 0, nil
		}
	}
	return role, nil
}

func allowCreateUser(c *Client) bool {
	if conf.Config.IsSupportingCLB() {
		return true
	}

	return syspar.IsTestMode()
}
