/*---------------------------------------------------------------------------------------------
 *  Copyright (c) IBAX. All rights reserved.
 *  See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

package querycost

import (
type QueryCoster interface {
	QueryCost(*model.DbTransaction, string, ...interface{}) (int64, error)
}

type ExplainQueryCoster struct {
}

func (*ExplainQueryCoster) QueryCost(transaction *model.DbTransaction, query string, args ...interface{}) (int64, error) {
	return explainQueryCost(transaction, true, query, args...)
}

type ExplainAnalyzeQueryCoster struct {
}

func (*ExplainAnalyzeQueryCoster) QueryCost(transaction *model.DbTransaction, query string, args ...interface{}) (int64, error) {
	return explainQueryCost(transaction, true, query, args...)
}

func GetQueryCoster(tp QueryCosterType) QueryCoster {
	switch tp {
	case ExplainQueryCosterType:
		return &ExplainQueryCoster{}
	case ExplainAnalyzeQueryCosterType:
		return &ExplainAnalyzeQueryCoster{}
	case FormulaQueryCosterType:
		return &FormulaQueryCoster{&DBCountQueryRowCounter{}}
	}
	return nil
}
