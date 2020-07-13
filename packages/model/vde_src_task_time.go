/*---------------------------------------------------------------------------------------------
 *  Copyright (c) IBAX. All rights reserved.
 *  See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
package model

type VDESrcTaskTime struct {

func (VDESrcTaskTime) TableName() string {
	return "vde_src_task_time"
}

func (m *VDESrcTaskTime) Create() error {
	return DBConn.Create(&m).Error
}

func (m *VDESrcTaskTime) Updates() error {
	return DBConn.Model(m).Updates(m).Error
}

func (m *VDESrcTaskTime) Delete() error {
	return DBConn.Delete(m).Error
}

func (m *VDESrcTaskTime) Get() (*VDESrcTaskTime, error) {
	err := DBConn.First(&m).Error
	return m, err
}

func (m *VDESrcTaskTime) GetAll() ([]VDESrcTaskTime, error) {
	var result []VDESrcTaskTime
	err := DBConn.Find(&result).Error
	return result, err
}
func (m *VDESrcTaskTime) GetOneByID() (*VDESrcTaskTime, error) {
	err := DBConn.Where("id=?", m.ID).First(&m).Error
	return m, err
}
