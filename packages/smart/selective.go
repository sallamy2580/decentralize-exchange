/*---------------------------------------------------------------------------------------------
 *  Copyright (c) IBAX. All rights reserved.
 *  See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
package smart

import (
	"fmt"
	"strings"

	"github.com/IBAX-io/go-ibax/packages/consts"
	"github.com/IBAX-io/go-ibax/packages/storage/sqldb"
	"github.com/IBAX-io/go-ibax/packages/storage/sqldb/querycost"
	"github.com/IBAX-io/go-ibax/packages/types"

	qb "github.com/IBAX-io/go-ibax/packages/storage/sqldb/queryBuilder"

	log "github.com/sirupsen/logrus"
)

func addRollback(sc *SmartContract, table, tableID, rollbackInfoStr string) error {
	rollbackTx := &sqldb.RollbackTx{
		BlockID:   sc.BlockData.BlockID,
		TxHash:    sc.TxHash,
		NameTable: table,
		TableID:   tableID,
		Data:      rollbackInfoStr,
	}
	sc.RollBackTx = append(sc.RollBackTx, rollbackTx)
	err := rollbackTx.Create(sc.DbTransaction)
	if err != nil {
		return logErrorDB(err, "creating rollback tx")
	}
	return nil
}

func (sc *SmartContract) selectiveLoggingAndUpd(fields []string, ivalues []interface{},
	table string, inWhere *types.Map, generalRollback bool, exists bool) (int64, string, error) {

	var (
		cost            int64
		rollbackInfoStr string
		logData         map[string]string
	)

	logger := sc.GetLogger()
	if generalRollback && sc.BlockData == nil {
		logger.WithFields(log.Fields{"type": consts.EmptyObject}).Error("Block is undefined")
		return 0, ``, fmt.Errorf(`it is impossible to write to DB when Block is undefined`)
	}
	for i, field := range fields {
		fields[i] = strings.ToLower(field)
	}
	sqlBuilder := &qb.SQLQueryBuilder{
		Entry:        logger,
		Table:        table,
		Fields:       fields,
		FieldValues:  ivalues,
		Where:        inWhere,
		TxEcoID:      sc.TxSmart.EcosystemID,
		KeyTableChkr: sqldb.KeyTableChecker{},
	}

	queryCoster := querycost.GetQueryCoster(querycost.FormulaQueryCosterType)
	if exists {
		selectQuery, err := sqlBuilder.GetSelectExpr()
		if err != nil {
			logger.WithFields(log.Fields{"error": err}).Error("on getting sql select statement")
			return 0, "", err
		}

		selectCost, err := queryCoster.QueryCost(sc.DbTransaction, selectQuery)
		if err != nil {
			logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": table, "query": selectQuery, "fields": fields, "values": ivalues, "where": inWhere}).Error("getting query total cost")
			return 0, "", err
		}

		logData, err = sqldb.GetOneRowTransaction(sc.DbTransaction, selectQuery).String()
		if err != nil {
			logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "query": selectQuery}).Error("getting one row transaction")
			return 0, "", err
		}
		cost += selectCost
		if len(logData) == 0 {
			logger.WithFields(log.Fields{"type": consts.NotFound, "err": errUpdNotExistRecord, "table": table, "fields": fields, "values": shortString(fmt.Sprintf("%+v", ivalues), 100), "where": inWhere, "query": shortString(selectQuery, 100)}).Error("updating for not existing record")
			return 0, "", errUpdNotExistRecord
		}
		if sqlBuilder.IsEmptyWhere() {
			logger.WithFields(log.Fields{"type": consts.NotFound,
				"error": errWhereUpdate}).Error("update without where")
			return 0, "", errWhereUpdate
		}
	}

	if !sqlBuilder.Where.IsEmpty() && len(logData) > 0 {
		var err error
		rollbackInfoStr, err = sqlBuilder.GenerateRollBackInfoString(logData)
		if err != nil {
			logger.WithFields(log.Fields{"error": err}).Error("on generate rollback info string for update")
			return 0, "", err
		}

		updateExpr, err := sqlBuilder.GetSQLUpdateExpr(logData)
		if err != nil {
			logger.WithFields(log.Fields{"error": err}).Error("on getting update expression for update")
			return 0, "", err
		}

		whereExpr, err := sqlBuilder.GetSQLWhereExpr()
		if err != nil {
			logger.WithFields(log.Fields{"error": err}).Error("on getting where expression for update")
			return 0, "", err
		}
		if !sc.CLB {
			updateQuery := `UPDATE "` + sqlBuilder.Table + `" SET ` + updateExpr + " " + whereExpr
			updateCost, err := queryCoster.QueryCost(sc.DbTransaction, updateQuery)
			if err != nil {
				logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "query": updateQuery}).Error("getting query total cost for update query")
				return 0, "", err
			}
			cost += updateCost
		}

		err = sqldb.Update(sc.DbTransaction, sqlBuilder.Table, updateExpr, whereExpr)
		if err != nil {
			logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "table": sqlBuilder.Table, "update": updateExpr, "where": whereExpr}).Error("getting update query")
			return 0, "", err
		}
		sqlBuilder.SetTableID(logData[`id`])
	} else {

		insertQuery, err := sqlBuilder.GetSQLInsertQuery(sqldb.NextIDGetter{Tx: sc.DbTransaction})
		if err != nil {
			logger.WithFields(log.Fields{"error": err}).Error("on build insert query")
			return 0, "", err
		}

		insertCost, err := queryCoster.QueryCost(sc.DbTransaction, insertQuery)
		if err != nil {
			logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "query": insertQuery}).Error("getting total query cost for insert query")
			return 0, "", err
		}

		cost += insertCost
		err = sqldb.GetDB(sc.DbTransaction).Exec(insertQuery).Error
		if err != nil {
			logger.WithFields(log.Fields{"type": consts.DBError, "error": err, "query": insertQuery}).Error("executing insert query")
			return 0, "", err
		}
	}

	if generalRollback {
		var tid string
		tid = sqlBuilder.TableID()
		if len(rollbackInfoStr) <= 0 {
			idNames := strings.SplitN(sqlBuilder.Table, `_`, 2)
			if len(idNames) == 2 {
				if sqlBuilder.KeyTableChkr.IsKeyTable(idNames[1]) {
					tid = sqlBuilder.TableID() + "," + sqlBuilder.GetEcosystem()
				}
			}
		}
		if err := addRollback(sc, sqlBuilder.Table, tid, rollbackInfoStr); err != nil {
			return 0, sqlBuilder.TableID(), err
		}
	}
	return cost, sqlBuilder.TableID(), nil
}

func (sc *SmartContract) insert(fields []string, ivalues []interface{},
	table string) (int64, string, error) {
	return sc.selectiveLoggingAndUpd(fields, ivalues, table, nil, !sc.CLB && sc.Rollback, false)
}

func (sc *SmartContract) updateWhere(fields []string, values []interface{},
	table string, where *types.Map) (int64, string, error) {
	return sc.selectiveLoggingAndUpd(fields, values, table, where, !sc.CLB && sc.Rollback, true)
}

func (sc *SmartContract) update(fields []string, values []interface{},
	table string, whereField string, whereValue interface{}) (int64, string, error) {
	return sc.updateWhere(fields, values, table, types.LoadMap(map[string]interface{}{
		whereField: fmt.Sprint(whereValue)}))
}

func shortString(raw string, length int) string {
	if len(raw) > length {
		return raw[:length]
	}

	return raw
}
