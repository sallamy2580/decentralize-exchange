/*---------------------------------------------------------------------------------------------
 *  Copyright (c) IBAX. All rights reserved.
 *  See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetMaxBlockID(t *testing.T) {
	var ret maxBlockResult
	err := sendGet(`maxblockid`, nil, &ret)
	assert.NoError(t, err)
}

func TestGetBlockInfo(t *testing.T) {
