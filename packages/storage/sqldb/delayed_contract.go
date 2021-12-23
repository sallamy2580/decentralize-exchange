/*---------------------------------------------------------------------------------------------
 *  Copyright (c) IBAX. All rights reserved.
 *  See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

package sqldb

const tableDelayedContracts = "1_delayed_contracts"
const availableDelayedContracts = 0

// DelayedContract represents record of 1_delayed_contracts table
type DelayedContract struct {
	ID         int64  `gorm:"primary_key;not null"`
	Contract   string `gorm:"not null"`
	KeyID      int64  `gorm:"not null"`
	BlockID    int64  `gorm:"not null"`
	EveryBlock int64  `gorm:"not null"`
	Counter    int64  `gorm:"not null"`
	HighRate   int64  `gorm:"not null"`
	Limit      int64  `gorm:"not null"`
	Delete     bool   `gorm:"not null"`
	Conditions string `gorm:"not null"`
}

// TableName returns name of table
func (DelayedContract) TableName() string {
	return tableDelayedContracts
}

// GetAllDelayedContractsForBlockID returns contracts that want to execute for blockID
func GetAllDelayedContractsForBlockID(blockID int64) ([]*DelayedContract, error) {
	var contracts []*DelayedContract
	if err := DBConn.Where("block_id <= ? and deleted = ?", blockID, availableDelayedContracts).Order("high_rate desc").Find(&contracts).Error; err != nil {
		return nil, err
	}
	return contracts, nil
}

// Get is retrieving model from database
func (dc *DelayedContract) Get(id int64) (bool, error) {
	return isFound(DBConn.Where("id = ?", id).First(dc))
}
