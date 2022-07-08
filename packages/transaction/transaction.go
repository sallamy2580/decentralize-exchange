/*---------------------------------------------------------------------------------------------
 *  Copyright (c) IBAX. All rights reserved.
 *  See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
package transaction

import (
	"bytes"
	"fmt"
	"math/rand"

	"github.com/IBAX-io/go-ibax/packages/pbgo"
	"github.com/IBAX-io/go-ibax/packages/storage/sqldb"
	"github.com/IBAX-io/go-ibax/packages/types"
	"github.com/shopspring/decimal"
)

// Transaction is a structure for parsing transactions
type Transaction struct {
	FullData []byte // full transaction, with type and data
	*InToCxt
	*OutCtx
	Inner TransactionCaller
}

// TransactionCaller is parsing transactions
type TransactionCaller interface {
	Init(*InToCxt) error
	Validate() error
	Action(*InToCxt, *OutCtx) error
	TxRollback() error
	txType() byte
	txHash() []byte
	txPayload() []byte
	txTime() int64
	txKeyID() int64
	txExpedite() decimal.Decimal
}

func (t *Transaction) Type() byte                { return t.Inner.txType() }
func (t *Transaction) Hash() []byte              { return t.Inner.txHash() }
func (t *Transaction) Payload() []byte           { return t.Inner.txPayload() }
func (t *Transaction) Timestamp() int64          { return t.Inner.txTime() }
func (t *Transaction) KeyID() int64              { return t.Inner.txKeyID() }
func (t *Transaction) Expedite() decimal.Decimal { return t.Inner.txExpedite() }

func (t *Transaction) IsSmartContract() bool {
	_, ok := t.Inner.(*SmartTransactionParser)
	return ok
}

func (t *Transaction) SmartContract() *SmartTransactionParser {
	return t.Inner.(*SmartTransactionParser)
}

// UnmarshallTransaction is unmarshalling transaction
func UnmarshallTransaction(buffer *bytes.Buffer) (*Transaction, error) {
	tx := &Transaction{}
	if err := tx.Unmarshall(buffer); err != nil {
		return nil, fmt.Errorf("parse transaction error: %w", err)
	}
	return tx, nil
}

func (tr *Transaction) WithOption(
	notifications types.Notifications,
	genBlock bool,
	blockHeader, preBlockHeader *types.BlockHeader,
	dbTransaction *sqldb.DbTransaction,
	rand *rand.Rand,
	txCheckLimits *Limits,
	sqlDbSavePoint int,
	opts ...TransactionOption) error {
	in := &InToCxt{
		SqlDbSavePoint: sqlDbSavePoint,
		TxCheckLimits:  txCheckLimits,
		Rand:           rand,
		DbTransaction:  dbTransaction,
		PreBlockHeader: preBlockHeader,
		BlockHeader:    blockHeader,
		GenBlock:       genBlock,
		Notifications:  notifications,
	}
	in.DbTransaction.BinLogSql = nil
	tr.InToCxt = in
	tr.OutCtx = &OutCtx{
		TxResult: &pbgo.TxResult{Hash: tr.Hash()},
	}
	return tr.Apply(opts...)
}

type TransactionOption func(b *Transaction) error

func (tr *Transaction) Apply(opts ...TransactionOption) error {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(tr); err != nil {
			return err
		}
	}
	return nil
}
