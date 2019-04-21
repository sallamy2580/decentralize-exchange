// +build linux freebsd darwin
// +build 386 amd64

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) IBAX. All rights reserved.
 *  See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

package daylight

import (
	"syscall"

	"github.com/IBAX-io/go-ibax/packages/converter"

	log "github.com/sirupsen/logrus"
)

// KillPid is killing process by PID
func KillPid(pid string) error {
	err := syscall.Kill(converter.StrToInt(pid), syscall.SIGTERM)
	if err != nil {
		log.WithFields(log.Fields{"pid": pid, "signal": syscall.SIGTERM}).Error("Error killing process with pid")
