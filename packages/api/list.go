/*---------------------------------------------------------------------------------------------
 *  Copyright (c) IBAX. All rights reserved.
 *  See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

package api

import (
	"errors"

	"github.com/IBAX-io/go-ibax/packages/script"

	"github.com/IBAX-io/go-ibax/packages/conf"
	"github.com/IBAX-io/go-ibax/packages/consts"
	"github.com/IBAX-io/go-ibax/packages/converter"
	"github.com/IBAX-io/go-ibax/packages/model"
	qb "github.com/IBAX-io/go-ibax/packages/model/queryBuilder"
	"github.com/IBAX-io/go-ibax/packages/smart"
	"github.com/IBAX-io/go-ibax/packages/template"
	"github.com/IBAX-io/go-ibax/packages/types"

	//"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

type listResult struct {
	Count int64               `json:"count"`
	List  []map[string]string `json:"list"`
}

type sumResult struct {
	Sum string `json:"sum"`
}

type listForm struct {
	paginatorForm
	rowForm
}

type listWhereForm struct {
	listForm
	Order   string `schema:"order"`
	InWhere string `schema:"where"`
}

type SumWhereForm struct {
	Column string `schema:"column"`
	Where  string `schema:"where"`
}

func (f *listForm) Validate(r *http.Request) error {
	if err := f.paginatorForm.Validate(r); err != nil {
		return err
	}
	return f.rowForm.Validate(r)
}

func (f *SumWhereForm) Validate(r *http.Request) error {
	if len(f.Column) > 0 {
		f.Column = converter.EscapeName(f.Column)
	}
	return nil
}

func checkAccess(tableName, columns string, client *Client) (table string, cols string, err error) {
	sc := smart.SmartContract{
		OBS: conf.Config.IsSupportingOBS(),
		VM:  script.GetVM(),
		TxSmart: &types.SmartContract{
			Header: &types.Header{
				EcosystemID: client.EcosystemID,
				KeyID:       client.KeyID,
				NetworkID:   conf.Config.LocalConf.NetworkID,
			},
		},
	}
	table, _, cols, err = sc.CheckAccess(tableName, columns, client.EcosystemID)
	return
}

func getListHandler(w http.ResponseWriter, r *http.Request) {
	form := &listForm{}
	if err := parseForm(r, form); err != nil {
		errorResponse(w, err, http.StatusBadRequest)
		return
	}

	params := mux.Vars(r)
	client := getClient(r)
	logger := getLogger(r)

	var (
		err   error
		table string
	)
	table, form.Columns, err = checkAccess(params["name"], form.Columns, client)
	if err != nil {
		errorResponse(w, err)
		return
	}
	q := model.GetTableQuery(params["name"], client.EcosystemID)

	if len(form.Columns) > 0 {
		q = q.Select("id," + form.Columns)
	}

	result := new(listResult)
	err = q.Count(&result.Count).Error
	if err != nil {
		logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": table}).Error("Getting table records count")
		errorResponse(w, errTableNotFound.Errorf(table))
		return
	}

	rows, err := q.Order("id ASC").Offset(form.Offset).Limit(form.Limit).Rows()
	if err != nil {
		logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": table}).Error("Getting rows from table")
		errorResponse(w, err)
		return
	}

	result.List, err = model.GetResult(rows)
	if err != nil {
		errorResponse(w, err)
		return
	}

	jsonResponse(w, result)
}

func getListWhereHandler(w http.ResponseWriter, r *http.Request) {
	form := &listWhereForm{}
	if err := parseForm(r, form); err != nil {
		errorResponse(w, err, http.StatusBadRequest)
		return
	}

	params := mux.Vars(r)
	client := getClient(r)
	logger := getLogger(r)

	var (
		err          error
		table, where string
	)
	table, form.Columns, err = checkAccess(params["name"], form.Columns, client)
	if err != nil {
		errorResponse(w, err)
		return
	}
	q := model.GetTableQuery(params["name"], client.EcosystemID)

	if len(form.Columns) > 0 {
		q = q.Select("id," + smart.PrepareColumns([]string{form.Columns}))
	}

	if len(form.InWhere) > 0 {
		inWhere, _, err := template.ParseObject([]rune(form.InWhere))
		switch v := inWhere.(type) {
		case string:
			if len(v) == 0 {
				where = `true`
			} else {
				errorResponse(w, errors.New(`Where has wrong format`))
				return
			}
		case map[string]interface{}:
			where, err = qb.GetWhere(types.LoadMap(v))
			if err != nil {
				errorResponse(w, err)
				return
			}
		case *types.Map:
			where, err = qb.GetWhere(v)
			if err != nil {
				errorResponse(w, err)
				return
			}
		default:
			errorResponse(w, errors.New(`Where has wrong format`))
			return
		}
		q = q.Where(where)
	}

	result := new(listResult)
	err = q.Count(&result.Count).Error

	if err != nil {
		logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": table}).Errorf("selecting rows from table %s select %s where %s", table, smart.PrepareColumns([]string{form.Columns}), where)
		errorResponse(w, errTableNotFound.Errorf(table))
		return
	}

	if len(form.Order) > 0 {
		rows, err := q.Order(form.Order).Offset(form.Offset).Limit(form.Limit).Rows()
		if err != nil {
			logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": table}).Error("Getting rows from table")
			errorResponse(w, err)
			return
		}
		result.List, err = model.GetResult(rows)
		if err != nil {
			errorResponse(w, err)
			return
		}
	} else {
		rows, err := q.Order("id ASC").Offset(form.Offset).Limit(form.Limit).Rows()
		if err != nil {
			logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": table}).Error("Getting rows from table")
			errorResponse(w, err)
			return
		}
		result.List, err = model.GetResult(rows)
		if err != nil {
			errorResponse(w, err)
			return
		}
	}

	jsonResponse(w, result)
}

func getnodeListWhereHandler(w http.ResponseWriter, r *http.Request) {
	form := &listWhereForm{}
	if err := parseForm(r, form); err != nil {
		errorResponse(w, err, http.StatusBadRequest)
		return
	}

	params := mux.Vars(r)
	client := getClient(r)
	logger := getLogger(r)

	var (
		err          error
		table, where string
	)
	table, form.Columns, err = checkAccess(params["name"], form.Columns, client)
	if err != nil {
		errorResponse(w, err)
		return
	}
	//q := model.GetTableQuery(params["name"], client.EcosystemID)
	q := model.GetTableListQuery(params["name"], client.EcosystemID)
	if len(form.Columns) > 0 {
		q = q.Select("id," + smart.PrepareColumns([]string{form.Columns}))
	}

	if len(form.InWhere) > 0 {
		inWhere, _, err := template.ParseObject([]rune(form.InWhere))
		switch v := inWhere.(type) {
		case string:
			if len(v) == 0 {
				where = `true`
			} else {
				errorResponse(w, errors.New(`Where has wrong format`))
				return
			}
		case map[string]interface{}:
			where, err = qb.GetWhere(types.LoadMap(v))
			if err != nil {
				errorResponse(w, err)
				return
			}
		case *types.Map:
			where, err = qb.GetWhere(v)
			if err != nil {
				errorResponse(w, err)
				return
			}
		default:
			errorResponse(w, errors.New(`Where has wrong format`))
			return
		}
		q = q.Where(where)
	}

	result := new(listResult)
	err = q.Count(&result.Count).Error

	if err != nil {
		logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": table}).Errorf("selecting rows from table %s select %s where %s", table, smart.PrepareColumns([]string{form.Columns}), where)
		errorResponse(w, errTableNotFound.Errorf(table))
		return
	}

	if len(form.Order) > 0 {
		rows, err := q.Order(form.Order).Offset(form.Offset).Limit(form.Limit).Rows()
		if err != nil {
			logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": table}).Error("Getting rows from table")
			errorResponse(w, err)
			return
		}
		result.List, err = model.GetNodeResult(rows)
		if err != nil {
			errorResponse(w, err)
			return
		}
	} else {
		rows, err := q.Order("id ASC").Offset(form.Offset).Limit(form.Limit).Rows()
		if err != nil {
			logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": table}).Error("Getting rows from table")
			errorResponse(w, err)
			return
		}
		result.List, err = model.GetNodeResult(rows)
		if err != nil {
			errorResponse(w, err)
			return
		}
	}

	jsonResponse(w, result)
}

func getsumWhereHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err          error
		table, where string
	)
	form := &SumWhereForm{}

	if err := parseForm(r, form); err != nil {
		errorResponse(w, err, http.StatusBadRequest)
		return
	}

	params := mux.Vars(r)
	client := getClient(r)
	logger := getLogger(r)

	table, form.Column, err = checkAccess(params["name"], form.Column, client)
	if err != nil {
		errorResponse(w, err)
		return
	}
	//q := model.GetTableQuery(params["name"], client.EcosystemID)
	//
	//if len(form.Columns) > 0 {
	//	q = q.Select("id," + smart.PrepareColumns([]string{form.Columns}))
	//}

	if len(form.Where) > 0 {
		inWhere, _, err := template.ParseObject([]rune(form.Where))
		switch v := inWhere.(type) {
		case string:
			if len(v) == 0 {
				where = `true`
			} else {
				errorResponse(w, errors.New(`Where has wrong format`))
				return
			}
		case map[string]interface{}:
			where, err = qb.GetWhere(types.LoadMap(v))
			if err != nil {
				errorResponse(w, err)
				return
			}
		case *types.Map:
			where, err = qb.GetWhere(v)
			if err != nil {
				errorResponse(w, err)
				return
			}
		default:
			errorResponse(w, errors.New(`Where has wrong format`))
			return
		}
		//q = q.Where(where)
	}

	count, err := model.GetSumColumnCount(table, form.Column, where)
	if err != nil {
		logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": table}).Errorf("selecting rows from table %s select %s where %s", table, smart.PrepareColumns([]string{form.Column}), where)
		errorResponse(w, err)
		return
	}

	result := new(sumResult)
	if count > 0 {
		sum, err := model.GetSumColumn(table, form.Column, where)
		if err != nil {
			logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": table}).Errorf("selecting rows from table %s select %s where %s", table, smart.PrepareColumns([]string{form.Column}), where)
			errorResponse(w, errTableNotFound.Errorf(table))
			return
		}
		result.Sum = sum
	}
	jsonResponse(w, result)
}
