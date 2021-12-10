package transaction

import (
	"bytes"
	"time"

	"github.com/IBAX-io/go-ibax/packages/model"
)

func ProcessQueueTransactionBatches(dbTransaction *model.DbTransaction, qs []*model.QueueTx) error {
	var (
		checkTime = time.Now().Unix()
		hashes    model.ArrHashes
		trxs      []*model.Transaction
		err       error
	)
	type badTxStruct struct {
		hash  []byte
		msg   string
		keyID int64
	}

	processBadTx := func(dbTx *model.DbTransaction) chan badTxStruct {
		ch := make(chan badTxStruct)

		go func() {
			for badTxItem := range ch {
				BadTxForBan(badTxItem.keyID)
				_ = MarkTransactionBad(dbTx, badTxItem.hash, badTxItem.msg)
			}
		}()

		return ch
	}

	txBadChan := processBadTx(dbTransaction)

	defer func() {
		close(txBadChan)
	}()

	for i := 0; i < len(qs); i++ {
		tx := &Transaction{}
		tx, err = UnmarshallTransaction(bytes.NewBuffer(qs[i].Data), true)
		if err != nil {
			if tx != nil {
				txBadChan <- badTxStruct{hash: tx.TxHash(), msg: err.Error(), keyID: tx.TxKeyID()}
			}
			continue
		}
		err = tx.Check(checkTime)
		if err != nil {
			txBadChan <- badTxStruct{hash: tx.TxHash(), msg: err.Error(), keyID: tx.TxKeyID()}
			continue
		}
		newTx := &model.Transaction{
			Hash:     tx.TxHash(),
			Data:     tx.FullData,
			Type:     int8(tx.TxType()),
			KeyID:    tx.TxKeyID(),
			Expedite: tx.TxExpedite(),
			Time:     tx.TxTime(),
			Verified: 1,
			Used:     0,
			Sent:     0,
		}
		trxs = append(trxs, newTx)
		hashes = append(hashes, qs[i].Hash)
	}

	if len(trxs) > 0 {
		errTx := model.CreateTransactionBatches(dbTransaction, trxs)
		if errTx != nil {
			return errTx
		}
	}
	if len(hashes) > 0 {
		errQTx := model.DeleteQueueTxs(dbTransaction, hashes)
		if errQTx != nil {
			return errQTx
		}
	}
	return nil
}
