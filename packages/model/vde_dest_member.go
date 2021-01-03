/*---------------------------------------------------------------------------------------------
 *  Copyright (c) IBAX. All rights reserved.
 *  See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
package model

	UpdateTime int64 `gorm:"not null" json:"update_time"`
	CreateTime int64 `gorm:"not null" json:"create_time"`
}

func (VDEDestMember) TableName() string {
	return "vde_dest_member"
}

func (m *VDEDestMember) Create() error {
	return DBConn.Create(&m).Error
}

func (m *VDEDestMember) Updates() error {
	return DBConn.Model(m).Updates(m).Error
}

func (m *VDEDestMember) Delete() error {
	return DBConn.Delete(m).Error
}

func (m *VDEDestMember) GetAll() ([]VDEDestMember, error) {
	var result []VDEDestMember
	err := DBConn.Find(&result).Error
	return result, err
}
func (m *VDEDestMember) GetOneByID() (*VDEDestMember, error) {
	err := DBConn.Where("id=?", m.ID).First(&m).Error
	return m, err
}

func (m *VDEDestMember) GetOneByPubKey(VDEPubKey string) (*VDEDestMember, error) {
	err := DBConn.Where("vde_pub_key=?", VDEPubKey).First(&m).Error
	return m, err
}

func (m *VDEDestMember) GetAllByType(Type int64) ([]VDEDestMember, error) {
	result := make([]VDEDestMember, 0)
	err := DBConn.Table("vde_dest_member").Where("vde_type = ?", Type).Find(&result).Error
	return result, err
}
